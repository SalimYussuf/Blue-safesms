import pytest

from safesms import MODEL_PATH, load


@pytest.fixture(scope="session")
def model():
    if not MODEL_PATH.exists():
        import train
        train.main()
    return load()
