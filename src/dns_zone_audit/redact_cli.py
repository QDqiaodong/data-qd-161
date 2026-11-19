DESCRIPTION='Offline redacted structural export of a single-zone snapshot for support attachments'
import argparse, ipaddress, json, sys
from pathlib import Path
from .common import read, save
from .redact import analyze

def run(source):
    data,_digest=read(source)
    return {'schema_version':1,'result':analyze(data)}

def _diagnostic(error):
    # Diagnostics must never echo input content: the duplicate-key message
    # from common.read embeds the key, a decode failure embeds a byte, and
    # the ipaddress error embeds the rejected address.
    if isinstance(error,UnicodeDecodeError):return 'input is not valid UTF-8'
    if isinstance(error,ipaddress.AddressValueError):return 'invalid IP address in input'
    text=str(error)
    if text.startswith('duplicate JSON key:'):return 'duplicate JSON key in input'
    return text

def main():
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.source.resolve()==args.output.resolve():raise ValueError('input and output must differ')
        report=run(args.source);save(args.output,report)
    except (ValueError,TypeError,KeyError,OSError,OverflowError,RecursionError) as error:
        print(_diagnostic(error),file=sys.stderr);return 2
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,allow_nan=False));return 0

if __name__=='__main__':raise SystemExit(main())
