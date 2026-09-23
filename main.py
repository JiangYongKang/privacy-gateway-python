from privacy_gateway.api import create_app
from privacy_gateway.clock import SystemClock
from privacy_gateway.seed import build_service

service = build_service(SystemClock())
app = create_app(service)
