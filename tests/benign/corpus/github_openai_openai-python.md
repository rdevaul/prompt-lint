# OpenAI Python API library

<!-- prettier-ignore -->
[)](https://pypi.org/project/openai/)

The OpenAI Python library provides convenient access to the OpenAI REST API from any Python 3.9+
application. The library includes type definitions for all request params and response fields,
and offers both synchronous and asynchronous clients powered by [httpx](https://github.com/encode/httpx).

It is generated from our [OpenAPI specification](https://github.com/openai/openai-openapi) with [Stainless](https://stainlessapi.com/).

## Documentation

The REST API documentation can be found on [platform.openai.com](https://platform.openai.com/docs/api-reference). The full API of this library can be found in [api.md](api.md).

## Installation

```sh
# install from PyPI
pip install openai
```

## Usage

The full API of this library can be found in [api.md](api.md).

The primary API for interacting with OpenAI models is the [Responses API](https://platform.openai.com/docs/api-reference/responses). You can generate text from the model with the code below.

```python
import os
from openai import OpenAI

client = OpenAI(
    # This is the default and can be omitted
    api_key=os.environ.get("OPENAI_API_KEY"),
)

response = client.responses.create(
    model="gpt-5.2",
    instructions="You are a coding assistant that talks like a pirate.",
    input="How do I check if a Python object is an instance of a class?",
)

print(response.output_text)
```

The previous standard (supported indefinitely) for generating text is the [Chat Completions API](https://platform.openai.com/docs/api-reference/chat). You can use that API to generate text from the model with the code below.

```python
from openai import OpenAI

client = OpenAI()

completion = client.chat.completions.create(
    model="gpt-5.2",
    messages=[
        {"role": "developer", "content": "Talk like a pirate."},
        {
            "role": "user",
            "content": "How do I check if a Python object is an instance of a class?",
        },
    ],
)

print(completion.choices[0].message.content)
```

While you can provide an `api_key` keyword argument,
we recommend using [python-dotenv](https://pypi.org/project/python-dotenv/)
to add `OPENAI_API_KEY="My API Key"` to your `.env` file
so that your API key is not stored in source control.
[Get an API key here](https://platform.openai.com/settings/organization/api-keys).

### Vision

With an image URL:

```python
prompt = "What is in this image?"
img_url = "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/2023_06_08_Raccoon1.jpg/1599px-2023_06_08_Raccoon1.jpg"

response = client.responses.create(
    model="gpt-5.2",
    input=[
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": prompt},
                {"type": "input_image", "image_url": f"{img_url}"},
            ],
        }
    ],
)
```

With the image as a base64 encoded string:

```python
import base64
from openai import OpenAI

clie