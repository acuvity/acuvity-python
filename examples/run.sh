#!/bin/bash -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python "$SCRIPT_DIR/basic_file.py"

echo "Running basic_text.py ..."
python "$SCRIPT_DIR/basic_text.py"

echo "Running guards.py ..."
python "$SCRIPT_DIR/guards.py"

echo "Running intermediate_multimodal.py ..."
python "$SCRIPT_DIR/intermediate_multimodal.py"

echo "Running specific_match_result_in_multirequest.py ..."
python "$SCRIPT_DIR/specific_match_result_in_multirequest.py"

echo "Running specific_text_gibberish.py ..."
python "$SCRIPT_DIR/specific_text_gibberish.py"

echo "Running specific_text_prompt_injection.py ..."
python "$SCRIPT_DIR/specific_text_prompt_injection.py"
