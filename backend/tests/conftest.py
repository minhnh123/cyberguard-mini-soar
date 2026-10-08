import pytest
import asyncio
from app.core.database import init_db
from app.seed_data.seed import seed_database


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """
    Test Isolation Fixture (Session Scope):
    Ensures that database schemas and initial playbooks are initialized
    before any individual test runs, allowing every test to be executed
    independently and in isolation without relying on test execution order.
    """
    loop = asyncio.new_event_loop()
    loop.run_until_complete(init_db())
    loop.run_until_complete(seed_database())
    loop.close()
