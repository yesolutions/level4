from level4.model import _manifest_schema


def test_schema():
    """Simple test to verify making schema doesn't blow up"""
    res = _manifest_schema()
    assert isinstance(res, str)
    return
