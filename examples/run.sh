#!/bin/bash -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Running file_prompt_all_types_guard_input.py ..."
python "$SCRIPT_DIR/file_prompt_all_types_guard_input.py"

echo "Running text_prompt_all_types_guard_input.py ..."
python "$SCRIPT_DIR/text_prompt_all_types_guard_input.py"

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

echo "Running piis.py ..."
python "$SCRIPT_DIR/piis.py"
