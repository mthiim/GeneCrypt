package net.thiim.gcbackend.sessions;

import org.springframework.stereotype.Component;

@Component
public class TimeSource {
	public long getTime()
	{
		return System.currentTimeMillis();
	}
}
