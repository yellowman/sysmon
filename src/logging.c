/* $Id: logging.c,v 1.1 2002/01/29 02:42:28 jared Exp $ */
#include "config.h"


void log_header()
{
	/*

	Sysmon-Uptime: %d/VERS/Date/now(time_t)/sysmond.UpTime.0
	Log-Type: %d
		1 = periodic, 2 = startup, 3 = shutdown

	 */
}

void log_object(struct hostinfo *obj_info)
{

	/*

	stats {
		object-stats "%s";
		dns-stats "%s";
		type-stats "%s";
		desc-stats "%s";
		uptime-pct "%f";
		times-up "%d";
		times-down "%d";
		poll-interval "%d";
	};

	 */

}

