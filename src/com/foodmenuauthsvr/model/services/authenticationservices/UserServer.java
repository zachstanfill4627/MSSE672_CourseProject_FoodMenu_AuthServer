package com.foodmenuauthsvr.model.services.authenticationservices;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.foodmenu.model.domain.User;
import com.foodmenu.model.domain.UserWrapper;
import com.foodmenuauthsvr.model.business.exceptions.ServiceLoadException;
import com.foodmenuauthsvr.model.business.exceptions.UserPrivilegesException;
import com.foodmenuauthsvr.model.business.managers.UserManager;
import com.foodmenuauthsvr.model.services.exceptions.UserServiceException;

public class UserServer {
	
	static Logger LOGGER = Logger.getLogger(UserServer.class);
	
	private static String propertiesFile = System.getProperty("user.dir") + "\\config\\application.properties";
	
	static {
		try (InputStream input = new FileInputStream(propertiesFile)) {
            Properties prop = new Properties();
            prop.load(input);
            if(new File(prop.getProperty("log4j2.properties")).exists()) {
            	System.setProperty("log4j.configurationFile", prop.getProperty("log4j2.properties"));
            	LOGGER.info("Loaded Log4J Properties from " + prop.getProperty("log4j2.properties"));
            } else {
            	System.setProperty("log4j.configurationFile", "config\\log4j2.properties");
            	LOGGER.error("System failed to load log4j2.properties file. Check configuration for more details");
            }
		} catch (Exception e) {
			System.setProperty("log4j.configurationFile", "config\\log4j2.properties");
			LOGGER.error("System failed to load log4j2.properties file. Check configuration for more details");
		}	
	}

    public static void main(String[] args) {
    	LOGGER.info("Starting Application");
    	
    	ServerSocket server = null;
  
        try {
  
            // server is listening on port 1234
            server = new ServerSocket(40008);
            server.setReuseAddress(true);
  
            // running infinite loop for getting client request
            while (true) {
  
                // socket object to receive incoming client requests
                Socket client = server.accept();
  
                // Displaying that new client is connected to server
                System.out.println("Spinning up new Thread for Client:  "
                                   + client.getInetAddress().getHostAddress() 
                                   + ":" + client.getPort());
  
                // create a new thread object
                ClientHandler clientSock
                    = new ClientHandler(client);
  
                // This thread will handle the client separately
                new Thread(clientSock).start();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if (server != null) {
                try {
                    server.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    // ClientHandler class
    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        
        private UserManager userManager = new UserManager();
        
        // Constructor
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }
        
        public void run() {
        	
        	
        	
            try {
                OutputStream outputStream = clientSocket.getOutputStream();
                InputStream inputStream = clientSocket.getInputStream();
                
                ObjectOutputStream objectOutputStream =  new ObjectOutputStream(outputStream);
                ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
                
                UserWrapper userWrapper = (UserWrapper) objectInputStream.readObject();
                
                try {
                	UserWrapper response = new UserWrapper();
                	
                	switch (userWrapper.getRequestType()) {
                		case 1:
							if(!userWrapper.getMiscString().equals("Secret_Code")) {
								userWrapper.getUser().setRole("user");
							}
	                		response = new UserWrapper(10, userManager.addNewUser(userWrapper.getUser()));
	                		break;
                		case 2:
                			if (!validateSession(userWrapper.getAuthenticatedUser().getEmailAddress(), userWrapper.getAuthToken())) {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			} else {
	                			if(userWrapper.getUser().getRole().equals("admin") && !validateRole(userWrapper.getAuthenticatedUser().getEmailAddress())) {
	                					userWrapper.getUser().setRole("user");
	                			}
		                		response = new UserWrapper(10, userManager.addNewUser(userWrapper.getUser()));
                			}
	                		break;
                		case 3:
                			if(userManager.authenticateUser(userWrapper.getEmail(), userWrapper.getPassword())) {
                				response = new UserWrapper(10, true);
                				response.setAuthToken(userManager.retrieveUserSessionKey(userWrapper.getEmail()));
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                		case 4:
                			System.out.println("Reset User Password (Untrusted) -- Functionality not built att");
                			break;
                		case 5:
                			System.out.println("Reset User Password (Trusted) -- Functionality not built att");
                			break;
                		case 6: 
                			if (validateSession(userWrapper.getAuthenticatedUser().getEmailAddress(), userWrapper.getAuthToken())){
                				User authUser = userManager.retrieveUser(userWrapper.getAuthenticatedUser().getEmailAddress());
                				System.out.println(authUser.toString());
                				userManager.setUser(authUser);
                				if(userManager.deleteUser(userWrapper.getUser())) {
                					response = new UserWrapper(10, true);
                				} else {
                					response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                				}
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                		case 7: 
                			if (validateSession(userWrapper.getAuthenticatedUser().getEmailAddress(), userWrapper.getAuthToken())){
                				User retrievedUser = userManager.retrieveUser(userWrapper.getMiscString());
                				if (retrievedUser.validateNoPassword()) { 
                					response = new UserWrapper(10, true, retrievedUser);
                				} else {
                					response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                				}
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                		case 8: 
                			if (validateSession(userWrapper.getEmail(), userWrapper.getAuthToken())){
                				response = new UserWrapper(10, true, userManager.retrieveUser(userWrapper.getEmail()));
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                		case 9: 
                			if (validateSession(userWrapper.getEmail(), userWrapper.getAuthToken())){
                				response = new UserWrapper(10, true,  userManager.retrieveAllUsers());
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                			
                		case 11: 
                			if (userManager.closeUserSession(userWrapper.getEmail())) {
                				response = new UserWrapper(10, true); 
                			} else {
                				response = new UserWrapper(10, false); // ADD ERROR MESSAGE
                			}
                			break;
                	}
                	
                	objectOutputStream.writeObject(response);
				} catch (ServiceLoadException | UserServiceException | UserPrivilegesException e) {
					e.printStackTrace();
				}
                
                objectInputStream.close();
                objectInputStream.close();
	            clientSocket.close();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            } 
        }
        
        public boolean validateSession(String email, String authToken) throws ServiceLoadException, UserServiceException {
        	if (userManager.retrieveUserSessionKey(email).equals(authToken)) {
        		LOGGER.trace(String.format("SessionKey Valid for %s\n", email));
        		return true;
        	} else {
        		LOGGER.trace(String.format("SessionKey Invalid for %s\n", email));
        		return false;
        	}
        }
        
        public boolean validateRole (String email)  throws ServiceLoadException, UserServiceException {
        	if(userManager.retrieveUser(email).getRole().equals("admin")) {
        		return true;
        	} else {
        		return false;
        	}
        }
        
    }

}
