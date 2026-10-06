"""Standalone profile selection, with no SOC registry or execution hooks."""

from collections.abc import Mapping

from network_security_ai.contracts import (
    DeploymentProfile,
    NetworkSecurityAIConfig,
    NetworkThreatPrediction,
    NetworkThreatPredictor,
    Top40Contract,
)
from network_security_ai.predictors import (
    DNNNetworkThreatPredictor,
    LightGBMNetworkThreatPredictor,
)


class NetworkSecurityAIAdapter:
    def __init__(self, predictor: NetworkThreatPredictor) -> None:
        self.predictor = predictor

    def predict(self, features: Mapping[str, object]) -> NetworkThreatPrediction:
        return self.predictor.predict(features)


def create_network_security_ai(
    config: NetworkSecurityAIConfig,
) -> NetworkSecurityAIAdapter | None:
    # Revalidate copied settings as Pydantic model_copy does not validate updates.
    config = NetworkSecurityAIConfig.model_validate(config.model_dump())
    if not config.enabled:
        return None
    contract = Top40Contract(config)
    predictor = (
        LightGBMNetworkThreatPredictor(config, contract)
        if config.profile == DeploymentProfile.DETECTION_QUALITY
        else DNNNetworkThreatPredictor(config, contract)
    )
    return NetworkSecurityAIAdapter(predictor)
