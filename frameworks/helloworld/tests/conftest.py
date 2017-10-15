import pytest
import sdk_repository
import sdk_security


@pytest.fixture(scope='session')
def configure_universe():
    yield from sdk_repository.universe_session()

@pytest.fixture(scope='session')
def configure_security(configure_universe):
    yield from sdk_security.security_session(
        framework_name='hello-world',
        extra_role_permissions=[
            {
                'linux_user': 'nobody',
                # Note, have to urlencode the slash.
                'role_name': 'slave_public%252Fhello-world-role'
            }
        ]
    )
