package net.thiim.gcbackend.enclave.impl.test;

import static org.mockito.ArgumentMatchers.any;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import junit.framework.TestCase;
import net.thiim.gcbackend.EndpointController;
import net.thiim.gcbackend.enclave.EnclaveException;
import net.thiim.gcbackend.enclave.EnclaveInstance;
import net.thiim.gcbackend.enclave.ExecuteQueryRequest;
import net.thiim.gcbackend.enclave.ExecuteQueryResponse;
import net.thiim.gcbackend.enclave.IEnclaveSystem;
import net.thiim.gcbackend.enclave.LaunchRequest;
import net.thiim.gcbackend.enclave.LaunchResponse;
import net.thiim.gcbackend.json.EnclaveLaunchData;
import net.thiim.gcbackend.persistence.User;
import net.thiim.gcbackend.persistence.UserRepository;
import net.thiim.gcbackend.sessions.Session;
import net.thiim.gcbackend.sessions.SessionControl;
import net.thiim.gcbackend.sessions.TimeSource;

@RunWith(SpringRunner.class)
public class SessionControlTest extends TestCase {

	@Test
	public void createAndFindSession() {
		SessionControl sc = new SessionControl(300000, new TimeSource());
		Session session = sc.createSession();
		Session session2 = sc.createSession();
		
		Session refSession = sc.getSession(session.getID());
		assertEquals(session, refSession);
		
		Session refSession2 = sc.getSession(session2.getID());
		assertEquals(session2, refSession2);
	}

	@Test
	public void sessionCleanup() throws Exception {
		final long[] fakeTime = new long[1];
		fakeTime[0] = System.currentTimeMillis();
		TimeSource ts = Mockito.mock(TimeSource.class);
		
		Mockito.when(ts.getTime()).then(new Answer<Long>() {
			@Override
			public Long answer(InvocationOnMock invocation) throws Throwable {
				return fakeTime[0];
			}
		});
		SessionControl sc = new SessionControl(30000, ts);
		
		Session session = sc.createSession();

		long start = ts.getTime();
		EnclaveInstance ei = Mockito.mock(EnclaveInstance.class);
		Mockito.doAnswer(new Answer<Void>() {
	        @Override
	        public Void answer(InvocationOnMock invocation) throws Throwable {
	        	long t = ts.getTime();
	        	long diff = t - start;
	        	assertEquals(diff, 31000);
	        	return null;
	        }
		}).when(ei).forceQuit();
		
		session.setEnclaveInstance(ei);
		
		fakeTime[0] += 10000;
		
		Session session2 = sc.createSession();
		// Old session should still be retrivable
		Session refSession = sc.getSession(session.getID());
		assertEquals(session, refSession);

		
		// Let time run even more
		fakeTime[0] += 21000;
		
		// Make sure thread notices it
		Thread.sleep(6000);
		
		// Cleanup should have happened now
		Mockito.verify(ei).forceQuit();

		refSession = sc.getSession(session.getID());
		assertNull(refSession);

		// No. 2 should still be retrievable
		Session refSession2 = sc.getSession(session2.getID());
		assertEquals(session2, refSession2);
	}

}
