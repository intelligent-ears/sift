import os
import yaml
from ml.triage.classifier import BetaClassifier

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05
}

class TemplateRanker:
    """
    TemplateRanker sorts template IDs based on the expected hit-rate
    from the Beta classifier multiplied by the template severity weight.
    """
    def __init__(self, classifier: BetaClassifier, templates_dir: str = None):
        self.classifier = classifier
        self.templates_dir = templates_dir or os.path.expanduser("~/.nuclei-templates")
        self.severity_cache = {}
        self.load_severities()

    def load_severities(self):
        """
        Walks the templates directory to pre-cache template severities.
        """
        if not os.path.exists(self.templates_dir):
            return
        for root, _, files in os.walk(self.templates_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    path = os.path.join(root, file)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if data and "id" in data:
                                sev = data.get("info", {}).get("severity", "info").lower()
                                self.severity_cache[data["id"]] = sev
                    except Exception:
                        pass

    def get_severity(self, template_id: str) -> str:
        return self.severity_cache.get(template_id, "info")

    def rank(self, template_ids: list) -> list:
        """
        Returns a sorted list of (template_id, score) tuples.
        """
        scored = []
        for tid in template_ids:
            hit_rate = self.classifier.get_expected_hit_rate(tid)
            sev = self.get_severity(tid)
            weight = SEVERITY_WEIGHTS.get(sev, 0.1)
            score = hit_rate * weight
            scored.append((tid, score))
        
        # Sort descending by score
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
