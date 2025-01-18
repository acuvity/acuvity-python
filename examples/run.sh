#!/bin/bash -e

echo "Running basic_file.py ..."
python examples/basic_file.py

echo "Running basic_text.py ..."
python examples/basic_text.py

echo "Running guards.py ..."
python examples/guards.py

echo "Running intermediate_multimodal.py ..."
python examples/intermediate_multimodal.py

echo "Running specific_match_result_in_multirequest.py ..."
python examples/specific_match_result_in_multirequest.py

echo "Running specific_text_gibberish.py ..."
python examples/specific_text_gibberish.py

echo "Running specific_text_prompt_injection.py ..."
python examples/specific_text_prompt_injection.py