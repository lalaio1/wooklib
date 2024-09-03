# wooklib Library Documentation

Welcome to the **wooklib** library documentation! This guide provides a comprehensive overview of how to use the **wooklib** library to send messages, manage webhooks, and handle various scenarios on Discord. This library offers both synchronous and asynchronous implementations for interacting with Discord webhooks, making it flexible and suitable for different needs.

## Table of Contents
1. [🚀 Installation](#installation)
2. [⚡ Quick Start](#quick-start)
3. [📚 Class Overview](#class-overview)
4. [🔧 Features](#features)
   - [Sending Messages](#sending-messages)
   - [Sending Rich Embeds](#sending-rich-embeds)
   - [Sending Files](#sending-files)
   - [Managing Webhooks](#managing-webhooks)
   - [Handling Errors](#handling-errors)
   - [Advanced Features](#advanced-features)
5. [💻 Examples](#examples)
6. [🛠️ Advanced Usage](#advanced-usage)
7. [💡 Tips and Best Practices](#tips-and-best-practices)
8. [📝 Changelog](#changelog)
9. [📄 License](#license)

---

## 🚀 Installation

To install the **wooklib** library, simply use pip:

```bash
pip install .
```

Ensure you have Python 3.6 or higher installed to use the latest features of the library.

---

## ⚡ Quick Start

Here's a quick example to get you started with the **wooklib** library:

```python
from wokklib import wooklib

# Initialize the webhook
webhook = wooklib(url="https://discord.com/api/webhooks/your_webhook_id")

# Send a simple message
webhook.send_message("Hello, Discord!")
```

This will send a message saying "Hello, Discord!" to the specified Discord channel.

---

## 📚 Class Overview

### wooklib

- **`wooklib(url, username=None, avatar_url=None, log_errors=False, timeout=None, proxies=None, user_agent=None, verbose=False)`**
  - The main class for interacting with Discord webhooks.
  - **Parameters**:
    - `url`: The Discord webhook URL.
    - `username`: Optional username to override the default webhook username.
    - `avatar_url`: Optional URL to override the default webhook avatar.
    - `log_errors`: If `True`, errors will be logged.
    - `timeout`: Request timeout in seconds.
    - `proxies`: Dictionary of proxies to use for the requests.
    - `user_agent`: Custom user agent for requests.
    - `verbose`: If `True`, detailed logs will be shown.

### Asyncwooklib

- **`Asyncwooklib(url, username=None, avatar_url=None, user_agent=None, timeout=None)`**
  - An asynchronous version of the `wooklib` class, using `aiohttp` for non-blocking requests.

### Mentioningwooklib

- **`Mentioningwooklib(url, username=None, avatar_url=None, log_errors=False, timeout=None, proxies=None, user_agent=None, verbose=False)`**
  - A subclass of `wooklib` that allows you to easily mention users or roles.

### Validatingwooklib

- **`Validatingwooklib(url, username=None, avatar_url=None, log_errors=False, timeout=None, proxies=None, user_agent=None, verbose=False)`**
  - A subclass of `wooklib` that includes validation for message content lengths.

### Cachedwooklib

- **`Cachedwooklib(url, username=None, avatar_url=None, timeout=None, max_cache_size=128, cache_ttl=300)`**
  - A subclass that caches messages to avoid duplicate sends within a specified time period.

---

## 🔧 Features

### Sending Messages

Sending a message with **wooklib** is straightforward:

```python
webhook = wooklib(url="https://discord.com/api/webhooks/your_webhook_id")
webhook.send_message("This is a test message!")
```

### Sending Rich Embeds

You can send rich embeds with a title, description, and other details:

```python
webhook.send_embed(
    title="Important Update",
    description="New features have been added!",
    color=0x00ff00,  # Optional: Hex color code
    fields=[
        {"name": "Feature 1", "value": "Details about feature 1", "inline": False},
        {"name": "Feature 2", "value": "Details about feature 2", "inline": False}
    ],
    footer="Footer text here",
    timestamp="2023-09-01T12:34:56Z"  # Optional: ISO 8601 timestamp
)
```

### Sending Files

You can also send files along with your messages:

```python
webhook.send_file(file_path="path/to/your/file.txt", content="Here is the file you requested!")
```

### Managing Webhooks

The **wooklib** library allows you to manage webhooks with the following methods:
- `modify_webhook`: Modify the webhook's name and avatar.
- `delete_webhook`: Delete the webhook.
- `get_webhook_info`: Retrieve information about the webhook.

```python
webhook.modify_webhook(name="New Webhook Name", avatar="path/to/avatar.png")
info = webhook.get_webhook_info()
webhook.delete_webhook()
```

### Handling Errors

Custom error classes are provided to handle different types of webhook-related errors, such as `WebhookNotFoundError`, `RateLimitExceededError`, and `InvalidWebhookURLError`.

Example:

```python
try:
    webhook.send_message("This is a test message!")
except InvalidWebhookURLError as e:
    print(f"Error: {e}")
```

### Advanced Features

The library includes advanced features such as exponential backoff, cache management, and asynchronous requests. These features are designed to make the library robust and versatile.

---

## 💻 Examples

### Example 1: Sending a Batch of Messages Asynchronously

```python
import asyncio
from wooklib import Asyncwooklib

async def main():
    webhook = Asyncwooklib(url="https://discord.com/api/webhooks/your_webhook_id")
    messages = ["Message 1", "Message 2", "Message 3"]
    await webhook.send_messages_batch(messages)

asyncio.run(main())
```

### Example 2: Sending a Mention with a Role ID

```python
webhook = Mentioningwooklib(url="https://discord.com/api/webhooks/your_webhook_id")
webhook.send_mention("Attention everyone!", role_id="123456789012345678")
```

---

## 🛠️ Advanced Usage

### Using a Proxy

If you need to use a proxy:

```python
webhook = wooklib(url="https://discord.com/api/webhooks/your_webhook_id")
webhook.set_proxy("http://yourproxy.com:8080")
webhook.send_message("Message sent through a proxy!")
```

### Custom Headers

Add custom headers to your requests:

```python
webhook.set_custom_headers({"Authorization": "Bearer your_token"})
webhook.send_message("Message with custom headers!")
```

### Rate Limiting with Exponential Backoff

The `ExponentialBackoffwooklib` class automatically handles rate limiting with exponential backoff:

```python
webhook = ExponentialBackoffwooklib(url="https://discord.com/api/webhooks/your_webhook_id")
webhook.send_message("Message with rate limit handling!")
```

---

## 💡 Tips and Best Practices

- **Handle Errors Gracefully:** Always handle exceptions to avoid crashing your application.
- **Use Asynchronous Methods for High Volume:** For high-frequency message sending, consider using the `Asyncwooklib` class to avoid blocking your application.
- **Respect Discord's Rate Limits:** Avoid sending too many requests too quickly to prevent being rate limited.

---

## 📝 Changelog

### Version 1.0.0

- Initial release with support for synchronous and asynchronous message sending.
- Added error handling and webhook management features.

### Version 1.1.0

- Added support for sending rich embeds and files.
- Introduced the `Cachedwooklib` class for caching messages.

---

## 📄 License

The **wooklib** library is licensed under the MIT License. See the `LICENSE` file for more information.
