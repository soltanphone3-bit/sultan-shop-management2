import pytest

from app.db import RLSContext


def test_login_context_is_exclusive():
    RLSContext(login=True).validate()
    with pytest.raises(ValueError):
        RLSContext(login=True, user_id=7).validate()


def test_owner_requires_authenticated_user():
    with pytest.raises(ValueError):
        RLSContext(is_owner=True).validate()
    RLSContext(user_id=1, is_owner=True).validate()


def test_branch_user_requires_branch():
    with pytest.raises(ValueError):
        RLSContext(user_id=3).validate()
    RLSContext(user_id=3, branch_id=2).validate()


def test_empty_context_is_rejected():
    with pytest.raises(ValueError):
        RLSContext().validate()


def test_context_ids_must_be_positive_integers():
    with pytest.raises(ValueError):
        RLSContext(user_id=0, is_owner=True).validate()
    with pytest.raises(ValueError):
        RLSContext(user_id=3, branch_id=-1).validate()
