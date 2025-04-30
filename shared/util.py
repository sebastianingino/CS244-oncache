def exp_range(start, end, mul):
    while start < end:
        yield start
        start *= mul
