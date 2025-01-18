#!/bin/bash -e

echo "Running basic_file.py ..."
python basic_file.py

echo "Running basic_text.py ..."
python basic_text.py

echo "Running guards.py ..."
python guards.py

echo "Running intermediate_multimodal.py ..."
python intermediate_multimodal.py

echo "Running specific_match_result_in_multirequest.py ..."
python specific_match_result_in_multirequest.py

echo "Running specific_text_gibberish.py ..."
python specific_text_gibberish.py

echo "Running specific_text_prompt_injection.py ..."
python specific_text_prompt_injection.py