#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import numpy as np


def naive_dist(p, q):
    square_distance = 0
    for p_i, q_i in zip(p, q):
        square_distance += (p_i - q_i) ** 2
    return square_distance ** 0.5

def simple_numpy_dist(p, q):
    return (np.sum((p - q) ** 2)) ** 0.5
