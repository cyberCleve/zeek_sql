#!/usr/bin/env python3

import pandas as pd
import gzip
import os
from sqlalchemy import create_engine


def read_logs(log=None):
    log_path = "/usr/local/zeek/logs/"
    log_cmd = f"ls -d {log_path}*/* | grep '{log}' | grep -v 'summary'"
    log_files = os.popen(log_cmd).read().strip().split("\n")

    def check_file_for_header(file):
        header = False
        file = file.strip()
        if file.endswith(".gz"):
            with gzip.open(file, "rt", encoding="utf-8") as f:
                lines = f.readlines()
        elif file.endswith(".log"):
            with open(file, "r") as f:
                lines = f.readlines()
        for line in lines:
            if line.startswith("#fields"):
                header = line.strip().split("\t")[1::]
                return header
        return False

    for file in log_files:
        header = check_file_for_header(file)
        if header:
            # read logs
            file_list = []
            for file in log_files:
                df = pd.read_csv(
                    file,
                    names=header, 
                    compression="infer",
                    comment="#",
                    delimiter="\t"
                )
                file_list.append(df)

            return pd.concat(file_list, axis=0, ignore_index=True)
    return False


def create_schema(df=None, log=None):
    db_string = f"sqlite:////{os.getcwd()}/zeek_logs.sqlite"
    engine = create_engine(db_string, echo=False)
    df.to_sql(f"{log}", con=engine)


logs = ["conn", "dns", "ssl"]
for log in logs:
    df = read_logs(log=log)
    if not type(df) == bool:
        create_schema(df=df, log=log)
