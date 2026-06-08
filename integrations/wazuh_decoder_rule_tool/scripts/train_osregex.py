"""
Wazuh OS_Regex Fine-Tuning Script for Ollama Models

This script converts the Modelfile.finetune MESSAGE pairs into a JSONL dataset
suitable for fine-tuning, then optionally runs the training.

Usage:
  # Step 1: Extract training data from Modelfile.finetune
  python scripts/train_osregex.py extract

  # Step 2: Fine-tune (requires Ollama 0.5+ or llama.cpp)
  python scripts/train_osregex.py train
"""

import re
import json
import sys
import os

MODELFILE_PATH = os.path.join(os.path.dirname(__file__), "..", "Modelfile.finetune")
DATASET_OUT = os.path.join(os.path.dirname(__file__), "..", "data", "osregex_train_full.jsonl")
VAL_DATASET_OUT = os.path.join(os.path.dirname(__file__), "..", "data", "osregex_val_full.jsonl")

# Fallback to smaller development datasets
if not os.path.exists(DATASET_OUT):
    DATASET_OUT = os.path.join(os.path.dirname(__file__), "..", "data", "osregex_train.jsonl")
if not os.path.exists(VAL_DATASET_OUT):
    VAL_DATASET_OUT = os.path.join(os.path.dirname(__file__), "..", "data", "osregex_val.jsonl")


def extract_training_data():
    """Parse Modelfile.finetune and extract MESSAGE user/assistant pairs as JSONL."""
    if not os.path.exists(MODELFILE_PATH):
        print(f"ERROR: {MODELFILE_PATH} not found")
        return False

    with open(MODELFILE_PATH) as f:
        content = f.read()

    # Extract all MESSAGE user/assistant pairs
    # Format: MESSAGE user "..." \n MESSAGE assistant """..."""
    pattern = r'MESSAGE user "([\s\S]*?)"\nMESSAGE assistant """([\s\S]*?)"""'
    pairs = re.findall(pattern, content)

    if not pairs:
        print("ERROR: No MESSAGE pairs found in Modelfile.finetune")
        return False

    print(f"Found {len(pairs)} training pairs")

    # Convert to OpenAI-style chat format
    os.makedirs(os.path.dirname(DATASET_OUT), exist_ok=True)

    # Split 90/10 train/val
    split = int(len(pairs) * 0.9)
    train_pairs = pairs[:split]
    val_pairs = pairs[split:]

    with open(DATASET_OUT, "w") as f:
        for user_msg, assistant_msg in train_pairs:
            amsg = assistant_msg.strip()
            # Assistant already includes ```xml wrapper — don't double-wrap
            if not amsg.startswith("```"):
                amsg = f"```xml\n{amsg}\n```"
            entry = {
                "messages": [
                    {
                        "role": "system",
                        "content": _get_system_prompt(),
                    },
                    {
                        "role": "user",
                        "content": user_msg.strip(),
                    },
                    {
                        "role": "assistant",
                        "content": amsg,
                    },
                ]
            }
            f.write(json.dumps(entry) + "\n")

    with open(VAL_DATASET_OUT, "w") as f:
        for user_msg, assistant_msg in val_pairs:
            amsg = assistant_msg.strip()
            if not amsg.startswith("```"):
                amsg = f"```xml\n{amsg}\n```"
            entry = {
                "messages": [
                    {
                        "role": "system",
                        "content": _get_system_prompt(),
                    },
                    {
                        "role": "user",
                        "content": user_msg.strip(),
                    },
                    {
                        "role": "assistant",
                        "content": amsg,
                    },
                ]
            }
            f.write(json.dumps(entry) + "\n")

    print(f"Training data: {DATASET_OUT} ({len(train_pairs)} examples)")
    print(f"Validation data: {VAL_DATASET_OUT} ({len(val_pairs)} examples)")
    return True


def _get_system_prompt() -> str:
    """Extract the SYSTEM prompt from Modelfile.finetune."""
    with open(MODELFILE_PATH) as f:
        content = f.read()
    m = re.search(r'SYSTEM """(.*?)"""', content, re.DOTALL)
    return m.group(1).strip() if m else "You are a Wazuh SIEM expert."


def run_training():
    """Run fine-tuning using Ollama's built-in train command."""
    if not os.path.exists(DATASET_OUT):
        print(f"ERROR: Run 'extract' first to create {DATASET_OUT}")
        return False

    print("\n" + "=" * 60)
    print("To fine-tune, run one of the following:")
    print("=" * 60)
    print()
    print("Option 1: Ollama 0.5+ (simplest)")
    print("-" * 40)
    print(f"""  ollama train \\
    --model qwen2.5:7b \\
    --dataset {DATASET_OUT} \\
    --output wazuh-osregex""")
    print()
    print("Option 2: Unsloth (Google Colab, free GPU)")
    print("-" * 40)
    print(f"""  # Upload {DATASET_OUT} to Colab
  # Use this notebook: https://github.com/unslothai/unsloth
  #
  # from unsloth import FastLanguageModel
  # model, tokenizer = FastLanguageModel.from_pretrained(
  #     "unsloth/qwen2.5-7b-bnb-4bit",
  #     max_seq_length=4096,
  # )
  # model = FastLanguageModel.get_peft_model(model, r=16)
  # from datasets import load_dataset
  # dataset = load_dataset("json", data_files="{DATASET_OUT}")
  # trainer = SFTTrainer(model=model, train_dataset=dataset["train"], ...)
  # trainer.train()""")
    print()
    print("Option 3: llama.cpp (local, more control)")
    print("-" * 40)
    print(f"""  # Convert dataset to GGUF format
  python convert-train-data.py {DATASET_OUT}
  # Fine-tune with LoRA
  ./finetune --model-base qwen2.5-7b.gguf \\
    --train-data {DATASET_OUT} \\
    --lora-out ./lora-osregex.gguf""")
    print()
    print("Option 4: Axolotl (advanced)")
    print("-" * 40)
    print(f"""  # Create config.yml:
  # model: Qwen/Qwen2.5-7B
  # datasets:
  #   - path: {DATASET_OUT}
  #     type: chat_template
  # micro_batch_size: 2
  # learning_rate: 2e-5
  # num_epochs: 3
  #
  # Then: accelerate launch -m axolotl.cli.train config.yml""")

    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/train_osregex.py <extract|train>")
        sys.exit(1)

    command = sys.argv[1]
    if command == "extract":
        success = extract_training_data()
        sys.exit(0 if success else 1)
    elif command == "train":
        success = run_training()
        sys.exit(0 if success else 1)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
