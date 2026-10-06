def main():
    import logging
    from waitress import serve
    from .web import create_app
    from .config import RAW_LIMIT, OUTPUT_LIMIT
    logging.getLogger("waitress").setLevel(logging.CRITICAL)
    print("Phishing Email Analyzer: http://127.0.0.1:5000 (Ctrl+C to stop)", flush=True)
    serve(create_app(), host="127.0.0.1", port=5000, threads=4,
          max_request_body_size=RAW_LIMIT, inbuf_overflow=RAW_LIMIT + 1024 * 1024,
          outbuf_overflow=OUTPUT_LIMIT + 1024 * 1024)


if __name__ == "__main__":
    main()
