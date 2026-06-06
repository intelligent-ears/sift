import os
import math
import json
import logging
from concurrent import futures
import redis
import grpc

# Import generated protobuf stubs
try:
	from ml.api import triage_pb2 as pb2
	from ml.api import triage_pb2_grpc as pb2_grpc
except ImportError:
	# Fallback if Python package path differs during runtime
	import api.triage_pb2 as pb2
	import api.triage_pb2_grpc as pb2_grpc

from ml.triage.classifier import BetaClassifier
from ml.triage.ranker import TemplateRanker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TriageServer")

class TriageService(pb2_grpc.TriageServiceServicer):
    def __init__(self, redis_client, templates_dir=None):
        self.redis = redis_client
        self.classifier = BetaClassifier(redis_client)
        self.ranker = TemplateRanker(self.classifier, templates_dir)
        self.learning_rate = 0.05

    def RankTemplates(self, request, context):
        try:
            template_ids = list(request.template_ids)
            logger.info(f"Ranking {len(template_ids)} templates")
            ranked = self.ranker.rank(template_ids)
            
            templates_resp = []
            for tid, score in ranked:
                templates_resp.append(pb2.ScoredTemplate(template_id=tid, score=score))
            
            return pb2.RankResponse(templates=templates_resp)
        except Exception as e:
            logger.error(f"Error in RankTemplates: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.RankResponse()

    def _get_lr_weights(self):
        weights_key = "sift:ml:lr:weights"
        try:
            data = self.redis.get(weights_key)
            if data:
                return json.loads(data)
        except Exception:
            pass
        
        # Default starting weights
        return {
            "bias": -1.0,
            "w_sev": -2.0,
            "w_fp": 3.0,
            "w_cms": 0.5,
            "w_ports": -0.1,
            "w_techs": -0.1
        }

    def _save_lr_weights(self, weights):
        weights_key = "sift:ml:lr:weights"
        try:
            self.redis.set(weights_key, json.dumps(weights))
        except Exception:
            pass

    def _get_module_fp_rate(self, module_name: str) -> float:
        stats_key = f"sift:ml:module_stats:{module_name}"
        try:
            data = self.redis.get(stats_key)
            if data:
                stats = json.loads(data)
                total = stats.get("total", 0)
                fp = stats.get("fp", 0)
                if total > 0:
                    return fp / total
        except Exception:
            pass
        return 0.1

    def ScoreFinding(self, request, context):
        try:
            finding_obj = request.finding
            ctx = request.target_context

            # Feature 1: Severity Score
            sev_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}
            sev_score = sev_map.get(finding_obj.severity.lower(), 0.1)

            # Feature 2: Historical FP Rate
            fp_rate = self._get_module_fp_rate(finding_obj.module_name)

            # Feature 3: Target context features
            has_cms = 1.0 if ctx.cms_type else 0.0
            ports_count = len(ctx.open_ports)
            techs_count = len(ctx.technologies)

            # Get weights
            weights = self._get_lr_weights()

            # Compute logit z
            z = (weights["bias"] +
                 weights["w_sev"] * sev_score +
                 weights["w_fp"] * fp_rate +
                 weights["w_cms"] * has_cms +
                 weights["w_ports"] * ports_count +
                 weights["w_techs"] * techs_count)

            # Logit to probability via sigmoid
            fp_prob = 1.0 / (1.0 + math.exp(-z))

            # Compute adjusted severity
            base_sev_score = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.0}
            base_sev = base_sev_score.get(finding_obj.severity.lower(), 0.0)
            adj_sev = base_sev * (1.0 - fp_prob)

            # Cache the features for training feedback in RecordOutcome step
            # We look up template_id in evidence dictionary if it exists
            template_id = finding_obj.evidence.get("template_id") if finding_obj.evidence else None
            if template_id:
                ctx_key = f"sift:ml:last_context:{template_id}"
                try:
                    self.redis.set(ctx_key, json.dumps({
                        "sev_score": sev_score,
                        "fp_rate": fp_rate,
                        "has_cms": has_cms,
                        "ports_count": ports_count,
                        "techs_count": techs_count
                    }))
                except Exception:
                    pass

            return pb2.ScoreResponse(false_pos_prob=fp_prob, adjusted_severity=adj_sev)
        except Exception as e:
            logger.error(f"Error in ScoreFinding: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.ScoreResponse()

    def RecordOutcome(self, request, context):
        try:
            template_id = request.template_id
            hit = request.hit
            analyst_confirmed = request.analyst_confirmed

            logger.info(f"Recording outcome for {template_id}: hit={hit}, confirmed={analyst_confirmed}")

            # 1. Update template Beta hit-rate parameters
            self.classifier.record_outcome(template_id, hit)

            # 2. Update online logistic regression weights if finding hit
            if hit:
                # y = 1.0 represents False Positive, y = 0.0 represents True Positive
                y = 1.0 if not analyst_confirmed else 0.0

                # Update module stats for historical FP tracking (default to nuclei_module)
                stats_key = "sift:ml:module_stats:nuclei_module"
                try:
                    data = self.redis.get(stats_key)
                    stats = {"total": 0, "fp": 0}
                    if data:
                        stats = json.loads(data)
                    stats["total"] = stats.get("total", 0) + 1
                    if y == 1.0:
                        stats["fp"] = stats.get("fp", 0) + 1
                    self.redis.set(stats_key, json.dumps(stats))
                except Exception:
                    pass

                # Retrieve saved features
                ctx_key = f"sift:ml:last_context:{template_id}"
                try:
                    ctx_data = self.redis.get(ctx_key)
                    if ctx_data:
                        ctx = json.loads(ctx_data)
                        sev_score = ctx["sev_score"]
                        fp_rate = ctx["fp_rate"]
                        has_cms = ctx["has_cms"]
                        ports_count = ctx["ports_count"]
                        techs_count = ctx["techs_count"]

                        weights = self._get_lr_weights()

                        z = (weights["bias"] +
                             weights["w_sev"] * sev_score +
                             weights["w_fp"] * fp_rate +
                             weights["w_cms"] * has_cms +
                             weights["w_ports"] * ports_count +
                             weights["w_techs"] * techs_count)
                        pred = 1.0 / (1.0 + math.exp(-z))

                        # SGD weight update
                        error = pred - y
                        weights["bias"] -= self.learning_rate * error
                        weights["w_sev"] -= self.learning_rate * error * sev_score
                        weights["w_fp"] -= self.learning_rate * error * fp_rate
                        weights["w_cms"] -= self.learning_rate * error * has_cms
                        weights["w_ports"] -= self.learning_rate * error * ports_count
                        weights["w_techs"] -= self.learning_rate * error * techs_count

                        self._save_lr_weights(weights)
                except Exception as ex:
                    logger.error(f"Failed SGD update step: {ex}")

            return pb2.OutcomeResponse(ok=True)
        except Exception as e:
            logger.error(f"Error in RecordOutcome: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.OutcomeResponse(ok=False)

def serve():
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", 6379))
    port = os.environ.get("GRPC_PORT", "50051")

    r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_TriageServiceServicer_to_server(TriageService(r), server)
    
    server.add_insecure_port(f"[::]:{port}")
    logger.info(f"Starting ML Triage gRPC server on port {port}...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
