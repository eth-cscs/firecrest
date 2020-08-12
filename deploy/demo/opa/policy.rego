package f7t.authz

import input
import data

default allow = false




allow {
	some some_user
	data.systems[input.system].users[some_user] == input.user

}