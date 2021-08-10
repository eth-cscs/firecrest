#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import logging
import datetime

logging.getLogger(__name__)

def check_sacctTime(sacctTime):
    # HH:MM[:SS] [AM|PM]
    # MMDD[YY] or MM/DD[/YY] or MM.DD[.YY]
    # MM/DD[/YY]-HH:MM[:SS]
    # YYYY-MM-DD[THH:MM[:SS]]

    if "/" in sacctTime:

        try:
            # try: MM/DD
            datetime.datetime.strptime(sacctTime, "%m/%d")
            # try: MM/DD/YY
            datetime.datetime.strptime(sacctTime, "%m/%d/%y")
            # try: MM/DD-HH:MM
            datetime.datetime.strptime(sacctTime, "%m/%d-%H:%M")
            # try: MM/DD-HH:MM:SS
            datetime.datetime.strptime(sacctTime, "%m/%d-%H:%M:%S")
            # try: MM/DD/YY-HH:MM
            datetime.datetime.strptime(sacctTime, "%m/%d/%y-%H:%M")
            # try: MM/DD/YY-HH:MM:SS
            datetime.datetime.strptime(sacctTime, "%m/%d/%y-%H:%M:%S")

            return True
        except ValueError as e:
            logging.error(e, exc_info=True)
            return False


    if ":" in sacctTime:

        try:
            # try: HH:MM
            datetime.datetime.strptime(sacctTime, "%H:%M")
            # try: HH:MM:SS
            datetime.datetime.strptime(sacctTime, "%H:%M:%S")
            # try: HH:MM:SS AM|PM
            datetime.datetime.strptime(sacctTime, "%H:%M:%S %p")
            # try: YYYY-MM-DDTHH:MM
            datetime.datetime.strptime(sacctTime, "%Y-%m-%dT%H:%M")
            # try: YYYY-MM-DDTHH:MM:SS
            datetime.datetime.strptime(sacctTime, "%Y-%m-%dT%H:%M:%S")
            return True
        except ValueError as e:
            logging.error(e, exc_info=True)
            return False

    if "." in sacctTime:
        try:
            # try: MM.DD
            datetime.datetime.strptime(sacctTime, "%m.%d")
            # try: MM.DD.YY
            datetime.datetime.strptime(sacctTime, "%m.%d.%y")
            return True
        except ValueError as e:
            logging.error(e, exc_info=True)
            return False

    if "-" not in sacctTime:
        try:
            #try: MMDD
            datetime.datetime.strptime(sacctTime, "%m%d")
            #try: MMDDYY
            datetime.datetime.strptime(sacctTime, "%m%d%y")
            return True
        except ValueError as e:
            logging.error(e, exc_info=True)
            return False

    try:
        # try: YYYY-MM-DD
        datetime.datetime.strptime(sacctTime, "%Y-%m-%d")
        return True
    except ValueError as e:
        logging.error(e, exc_info=True)
        return False



def check_jobTime(jobTime):
    # try to parse correctly the HH:MM:SS time format
    # acceptable formats are: MM MM:SS HH:MM:SS DD-HH DD-HH:MM DD-HH:MM:SS
    # time.strptime("15:02","%H:%M")

    if ":" not in jobTime and "-" not in jobTime:
        # asumes is just minutes:
        try:
            mm = int(jobTime) # exception stands for ValueError int convertion

            if mm < 1: # if minutes smaller than 1
                return False

        except ValueError as ve:
            logging.error(ve, exc_info=True)
            return False

        return True

    if ":" not in jobTime and "-" in jobTime:
        # asumes is DD-HH
        try:
            [dd,hh] = jobTime.split("-")

            dd = int(dd) # exception stands for ValueError int convertion
            hh = int(hh)

            if hh<0 or hh > 23: #if hours is bigger than one day hour or smaller than 0
                return False

            if dd < 0:
                return False

        except Exception as e:
            logging.error(e, exc_info=True)
            return False

        return True

    if ":" in jobTime and "-" not in jobTime:
        # asumes is HH:MM:SS or MM:SS

        splittedJobTime = jobTime.split(":")

        if len(splittedJobTime) == 2:
            # MM:SS
            [mm,ss] = splittedJobTime

            try:
                mm = int(mm)
                ss = int(ss)

                if mm < 0:
                    return False
                if ss < 0 or ss > 59:
                    return False
            except Exception as e:
                logging.error(e, exc_info=True)
                return False

            return True

        if len(splittedJobTime) == 3:
            # HH:MM:SS

            [hh,mm,ss] = splittedJobTime

            try:
                hh = int(hh)
                mm = int(mm)
                ss = int(ss)

                if hh < 0:
                    return False

                if mm < 0 or mm > 59:
                    return False
                if ss < 0 or ss > 59:
                    return False
            except Exception as e:
                logging.error(e, exc_info=True)
                return False

            return True

        return False


    # last assumed option is jobTime with - and : --> DD-HH:MM or DD-HH:MM:SS

    try:
        [dd,rest] = jobTime.split("-")

        dd = int(dd)
        if dd < 0:
            return  False

        splittedJobTime = rest.split(":")

        if len(splittedJobTime) == 2:
            # MM:SS
            [mm, ss] = splittedJobTime

            try:
                mm = int(mm)
                ss = int(ss)

                if mm < 0:
                    return False
                if ss < 0 or ss > 59:
                    return False
            except Exception as e:
                logging.error(e, exc_info=True)
                return False

            return True

        if len(splittedJobTime) == 3:
            # HH:MM:SS

            [hh, mm, ss] = splittedJobTime

            try:
                hh = int(hh)
                mm = int(mm)
                ss = int(ss)

                if hh < 0:
                    return False

                if mm < 0 or mm > 59:
                    return False
                if ss < 0 or ss > 59:
                    return False
            except Exception as e:
                logging.error(e, exc_info=True)
                return False

            return True

        return False


    except Exception as e:
        logging.error(e, exc_info=True)

        return False
