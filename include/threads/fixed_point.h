#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

int convert_int_to_fixed (int n) {
    return n * F;
}

int convert_fixed_to_int (int x) {
    return x / F;
}

int convert_fixed_to_int_round (int x) {
    if (x >= 0) { return (x + F / 2) / F; }
    else { return (x - F / 2) / F; }
}

int add_fixed_fixed (int x, int y) {
    return x + y;
}

int subtract_fixed_fixed (int x, int y) {
    return x - y;
}

int add_fixed_int (int x, int n) {
    return x + n * F;
}

int subtract_fixed_int (int x, int n) {
    return x - n * F;
}

int multiple_fixed_fixed (int x, int y) {
    return ((int64_t) x ) * y / F;
}

int multiple_fixed_int (int x, int n) {
    return x * n;
}

int divide_fixed_fixed (int x, int y) {
    return ((int64_t) x) * F / y;
}

int divide_fixed_int (int x, int n) {
    return x / n;
}