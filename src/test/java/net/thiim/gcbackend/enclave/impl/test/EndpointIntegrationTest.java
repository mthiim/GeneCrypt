package net.thiim.gcbackend.enclave.impl.test;

import static org.mockito.ArgumentMatchers.any;

import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
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

@RunWith(SpringRunner.class)
public class EndpointIntegrationTest extends TestCase {
	@MockBean
	private UserRepository mockRepository;

	@MockBean
	private IEnclaveSystem enclaveSystem;

	@MockBean
	private  SessionControl mockSessionControl;

	@TestConfiguration
	static class EmployeeServiceImplTestContextConfiguration {

		@Bean
		public EndpointController employeeService() {
			return new EndpointController();
		}
	}

	@Autowired
	private EndpointController endpointController;

	@Test
	public void newUser() {
		Mockito.when(mockRepository.save(any(User.class))).then(new Answer<User>() {
			@Override
			public User answer(InvocationOnMock invocation) throws Throwable {
				User u = invocation.getArgument(0);
				u.id = "123";
				return u;
			}
		});

		String id = endpointController.newUser("pubk");
		assertEquals("123", id);
		ArgumentCaptor<User> argumentCaptor = ArgumentCaptor.forClass(User.class);

		Mockito.verify(mockRepository).save(argumentCaptor.capture());
		assertEquals("pubk",argumentCaptor.getValue().getPubkey());
	}

	@Test
	public void storeGenome() {
		User alex = new User("pubk");
		alex.id = "1234";

		Mockito.when(mockRepository.findById("1234")).thenReturn(Optional.of(alex));

		ResponseEntity<String> resp = endpointController.storeGenome("1234", "encGenome", "encGenomeKey", "encGenomeIV");
		assertEquals(HttpStatus.OK, resp.getStatusCode());

		// Verify
		Mockito.verify(mockRepository).findById("1234");

		ArgumentCaptor<User> argumentCaptor = ArgumentCaptor.forClass(User.class);
		Mockito.verify(mockRepository).save(argumentCaptor.capture());

		User u = argumentCaptor.getValue();
		assertEquals("1234", u.getID());
		assertEquals("encGenome", u.getEncryptedGenome());
		assertEquals("encGenomeIV", u.getEncryptedGenomeIV());
		assertEquals("encGenomeKey", u.getEncryptedGenomeKey());
	}

	@Test
	public void launchEnclave() throws EnclaveException {
		User alex = new User("pubk");
		alex.id = "1234";
		Mockito.when(mockRepository.findById("1234")).thenReturn(Optional.of(alex));

		EnclaveInstance mockEnclaveInstance = Mockito.mock(EnclaveInstance.class);
		LaunchResponse launchResponse = new LaunchResponse();
		launchResponse.quoteData = "quoteData";
		launchResponse.quoteSignature = "quoteSignature";
		launchResponse.instance = mockEnclaveInstance;

		Session session = new Session(System.currentTimeMillis());
		Mockito.when(enclaveSystem.launch(any())).thenReturn(launchResponse);
		Mockito.when(mockSessionControl.createSession()).thenReturn(session);

		ResponseEntity<EnclaveLaunchData> resp = endpointController.launchEnclave("1234", "nonce", "receiverPublicKey");
		assertEquals(HttpStatus.OK, resp.getStatusCode());

		// Verify
		Mockito.verify(mockRepository).findById("1234");

		ArgumentCaptor<LaunchRequest> argumentCaptor = ArgumentCaptor.forClass(LaunchRequest.class);
		Mockito.verify(enclaveSystem).launch(argumentCaptor.capture());

		LaunchRequest lr = argumentCaptor.getValue();
		assertEquals("nonce", lr.nonce);
		assertEquals("receiverPublicKey", lr.receiverPublicKey);

		Mockito.verify(mockSessionControl).createSession();
		assertEquals(alex, session.getUser());
		assertEquals(mockEnclaveInstance, session.getEnclaveInstance());
	}

	@Test
	public void executeQuery() throws EnclaveException {
		Session session = new Session(System.currentTimeMillis());
		User alex = new User();
		alex.setEncryptedGenome("genome");
		alex.setEncryptedGenomeIV("iv");
		alex.setEncryptedGenomeKey("key");

		session.setUser(alex);
		EnclaveInstance mockEnclaveInstance = Mockito.mock(EnclaveInstance.class);
		session.setEnclaveInstance(mockEnclaveInstance);

		Mockito.when(mockSessionControl.getSession(session.getID())).thenReturn(session);

		ExecuteQueryResponse resp = new ExecuteQueryResponse();
		resp.result = "result";

		Mockito.when(mockEnclaveInstance.executeQuery(any())).thenReturn(resp);

		ResponseEntity<String> res = endpointController.executeQuery(session.getID(), "reencrypted");
		assertEquals(HttpStatus.OK, res.getStatusCode());
		assertEquals("result", res.getBody());


		Mockito.verify(mockSessionControl).getSession(session.getID());

		ArgumentCaptor<ExecuteQueryRequest> argumentCaptor = ArgumentCaptor.forClass(ExecuteQueryRequest.class);
		Mockito.verify(mockEnclaveInstance).executeQuery(argumentCaptor.capture());

		ExecuteQueryRequest eqr = argumentCaptor.getValue();
		assertEquals("genome", eqr.encryptedGenome);
		assertEquals("reencrypted", eqr.encryptedGenomeKey);
		assertEquals("iv", eqr.encryptedGenomeIV);
	}

}
