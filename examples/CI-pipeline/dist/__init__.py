import numpy as np


def naive_dist(p, q):
    square_distance = 0
    for p_i, q_i in zip(p, q):
        square_distance += (p_i - q_i) ** 2
    return square_distance ** 0.5

def simple_numpy_dist(p, q):
    return (np.sum((p - q) ** 2)) ** 0.5
