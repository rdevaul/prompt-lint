<div align="center">

<img src="./docs/assets/logo.svg" alt="Mistral AI" height="100"/>

<br/>
<br/>

# Mistral-common

[](https://pypi.org/project/mistral-common/)
[](https://github.com/mistralai/mistral-common/actions/workflows/lint_build_test.yaml)
[](https://mistralai.github.io/mistral-common/)
[](https://www.python.org/downloads/)
[](./LICENCE)

</div>

## What is it? 

**mistral-common** is a set of tools to help you work with [Mistral AI](https://mistral.ai/) models.

We open-source the tokenizers, validation and normalization code that can be used with our models.

This ensures that you can take full advantage of our models for the following features:

- **tokenization** of text, images and tools calls.
- **validation and normalization** of requests, messages, tool calls, and responses. This is built on top of the [Pydantic](https://docs.pydantic.dev/latest/) library.

We also version our tokenizers to guarantee backward compatibility for the models that we release.

## For who ?

This library is for you if you want to:

- use our models in your own application.
- build your own models and want to use the same tokenization and validation code as we do.

## How to use it ?

You can install the library using pip:
```sh
pip install mistral-common
```

We propose different dependencies to install depending on your needs:
- `image`: to use the image tokenizers.
- `audio`: to use the audio tokenizers.
- `hf-hub`: to download the tokenizers from the Hugging Face Hub.
- `sentencepiece`: to allow the use of SentencePiece tokenizers. This is now optional as we only release `Tekken` tokenizers for recent models.
- \[Experimental\] `server`: to use our tokenizers in a server mode.

Each dependency is optional and can be installed separately or all together using the following commands:
```sh
pip install "mistral-common[image]"
pip install "mistral-common[audio]"
pip install "mistral-common[hf-hub]"
pip install "mistral-common[sentencepiece]"
pip install "mistral-common[server]"
pip install "mistral-common[image,audio,hf-hub,sentencepiece,server]"
```

For more information, please refer to the [documentation](https://mistralai.github.io/mistral-common/).

## How to contribute ?

We welcome contributions to this library. All of our features are tested to ensure best usage. But if you encounter a bug, find difficulties in using `mistral-common`, please open an issue on our [GitHub repository](https://github.com/mistralai/mistral-common/issues).

If you want to contribute to the code, please fork the repository and open a pull request. We will review your changes and merge them if they are relevant to the library.

```sh
# Clone the repository
git clone https://github.com/<your_fork_username>/mistral-common.git
cd mistral-common

# Create a virtual environment and install the dependencies
uv venv
source .venv/bin/activate
uv sync --frozen --all-extras --group dev # --group docs if you want to build the documentation

# Install the pre-commit hooks
uv run