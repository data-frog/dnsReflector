#include "ref_time.h"

void time_to_str(char *timebuf,const char*format )
{
	time_t now;
	struct tm *tm_now;
	assert(timebuf!=NULL&&format!=NULL);
	time(&now);
	tm_now = localtime(&now);
	strftime( timebuf, 100,format,tm_now );
	return ;
}


	int32_t
gmt2local (time_t t)
{
	int dt, dir;
	struct tm *gmt, *loc;
	struct tm sgmt;

	if (t == 0)
		t = time (NULL);
	gmt = &sgmt;
	*gmt = *gmtime (&t);
	loc = localtime (&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
		(loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}


/* *************************************** */
/*
 * The time difference in microseconds
 */
	long
delta_time (struct timeval *now, struct timeval *before)
{
	time_t delta_seconds;
	time_t delta_microseconds;

	/*
	 * compute delta in second, 1/10's and 1/1000's second units
	 */
	delta_seconds = now->tv_sec - before->tv_sec;
	delta_microseconds = now->tv_usec - before->tv_usec;

	if (delta_microseconds < 0)
	{
		/* manually carry a one from the seconds field */
		delta_microseconds += 1000000;	/* 1e6 */
		--delta_seconds;
	}
	return ((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

