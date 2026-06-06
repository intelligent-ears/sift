import json

class BetaClassifier:
    """
    BetaClassifier manages a per-template Bayesian hit-rate tracker
    using a Beta distribution, persisted to Redis.
    """
    def __init__(self, redis_client):
        self.redis = redis_client

    def _get_key(self, template_id: str) -> str:
        return f"sift:ml:template:{template_id}"

    def get_beta_params(self, template_id: str):
        """
        Returns the (alpha, beta) parameters for the template.
        Defaults to (1.0, 1.0) representing a uniform prior.
        """
        key = self._get_key(template_id)
        try:
            data = self.redis.get(key)
            if data:
                stats = json.loads(data)
                return float(stats.get("alpha", 1.0)), float(stats.get("beta", 1.0))
        except Exception:
            # Fallback to defaults on connection/parsing errors
            pass
        return 1.0, 1.0

    def record_outcome(self, template_id: str, hit: bool) -> tuple:
        """
        Increments alpha (on hit) or beta (on miss) and persists it.
        """
        alpha, beta = self.get_beta_params(template_id)
        if hit:
            alpha += 1.0
        else:
            beta += 1.0
        
        key = self._get_key(template_id)
        try:
            self.redis.set(key, json.dumps({"alpha": alpha, "beta": beta}))
        except Exception:
            pass
        return alpha, beta

    def get_expected_hit_rate(self, template_id: str) -> float:
        """
        Calculates the expectation of the Beta distribution: alpha / (alpha + beta).
        """
        alpha, beta = self.get_beta_params(template_id)
        return alpha / (alpha + beta)
