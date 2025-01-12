import pytest

from acuvity.models.extraction import Extraction, Textualdetection
from acuvity.responseprocessor.parser import ResponseParser


@pytest.fixture
def parser():
    return ResponseParser()

def test_exploit_valid_value(parser):
    extraction = Extraction(
        exploits={
            'prompt_injection': 0.85
        }
    )
    guard_name = 'prompt_injection'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.85

def test_exploit_no_value(parser):
    extraction = Extraction(
        exploits={
            'jail_break': 0.75
        }
    )
    guard_name = 'prompt_injection'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is False
    assert value == 0

def test_exploit_empty_section(parser):
    extraction = Extraction(
        exploits=None
    )
    guard_name = 'prompt_injection'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is False
    assert value == 0

def test_topic_toxicity(parser):
    extraction = Extraction(
        topics={
            'content/toxic': 0.8
        }
    )
    guard_name = 'toxicity'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.8

def test_topic_bias(parser):
    extraction = Extraction(
        topics={
            'content/bias': 0.7
        }
    )
    guard_name = 'bias'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.7

def test_topic_harmful_content(parser):
    extraction = Extraction(
        topics={
            'content/harmful': 0.6
        }
    )
    guard_name = 'harmful_content'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.6

def test_topic_image_classifier(parser):
    extraction = Extraction(
        topics={
            'image/classifier': 0.9
        }
    )
    guard_name = 'image_classifier'
    match_name = 'classifier'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.9

def test_topic_corporate_classifier(parser):
    extraction = Extraction(
        topics={
            'department/corporate': 0.85
        }
    )
    guard_name = 'corporate_classifier'
    match_name = 'corporate'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.85

def test_topic_content_classifier(parser):
    extraction = Extraction(
        topics={
            'category/content': 0.95
        }
    )
    guard_name = 'content_classifier'
    match_name = 'content'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.95

def test_topic_content_classifier_no_match(parser):
    extraction = Extraction(
        topics={
            'category/content': 0.97,
            'category/content-2': 0.95
        }
    )
    guard_name = 'content_classifier'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.97

def test_language_gibberish(parser):
    extraction = Extraction(
        languages={
            'gibberish': 0.5
        }
    )
    guard_name = 'gibberish'
    exists, value = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 0.5

def test_language_valid_match(parser):
    extraction = Extraction(
        languages={
            'english': 0.9
        }
    )
    guard_name = 'language'
    match_name = 'english'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.9

def test_language_no_value(parser):
    extraction = Extraction(
        languages={
            'spanish': 0.7
        }
    )
    guard_name = 'language'
    match_name = 'english'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is False
    assert value == 0.0

def test_language_empty_section(parser):
    extraction = Extraction(
        languages=None
    )
    guard_name = 'language'
    match_name = 'english'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is False
    assert value == 0.0

def test_intent_valid_match(parser):
    extraction = Extraction(
        intent={
            'buy_product': 0.95
        }
    )
    guard_name = 'generic_classifier'
    match_name = 'buy_product'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.95

def test_intent_no_match(parser):
    extraction = Extraction(
        intent={
            'sell_product': 0.85
        }
    )
    guard_name = 'generic_classifier'
    match_name = 'buy_product'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 1.0

def test_intent_empty_section(parser):
    extraction = Extraction(
        intent=None
    )
    guard_name = 'generic_classifier'
    match_name = 'buy_product'
    exists, value = parser.get_value(extraction, guard_name, match_name)

    assert exists is False
    assert value == 0.0

def test_pii_with_match(parser):
    extraction = Extraction(
        pi_is={
            'email': 0.9
        },
        detections=[
            Textualdetection(type='PII', name='email', score=0.9),
            Textualdetection(type='PII', name='email', score=0.8)
        ]
    )
    guard_name = 'pii_detector'
    match_name = 'email'
    exists, value, count = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.9
    assert count == 2

def test_pii_without_match(parser):
    extraction = Extraction(
        pi_is={
            'email': 0.9
        },
        detections=[
            Textualdetection(type='PII', name='phone', score=0.7)
        ]
    )
    guard_name = 'pii_detector'
    match_name = 'email'
    exists, value, count = parser.get_value(extraction, guard_name, match_name)

    assert exists is True
    assert value == 0.9
    assert count == 1

def test_pii_no_match_name(parser):
    extraction = Extraction(
        pi_is={
            'email': 0.9,
            'phone': 0.8
        }
    )
    guard_name = 'pii_detector'
    exists, value, count = parser.get_value(extraction, guard_name)

    assert exists is True
    assert value == 1.0
    assert count == 2

def test_pii_empty_section(parser):
    extraction = Extraction(
        pi_is=None,
        detections=None
    )
    guard_name = 'pii_detector'
    match_name = 'email'
    exists, value, count = parser.get_value(extraction, guard_name, match_name)

    assert exists is False
    assert value == 0.0
    assert count == 0

def test_secrets(parser):
    extraction = Extraction(
        secrets={
            "credentials": 1.0
        }
    )
    guard_name = 'secrets_detector'
    exists = parser.get_value(extraction, guard_name)

    assert exists is True
