from argparse import ArgumentParser

def get_arg_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port")
    parser.add_argument("--use-ssl", action="store_true", help="Enable SSL/TLS")
    return parser
