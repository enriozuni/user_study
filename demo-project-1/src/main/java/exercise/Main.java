package exercise;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Main {

	static final String DB_URL = "168.192.0.1";
	static final String USER = "admin";
	static final String PASS = "admin123";
	
	public static void main(String[] args) throws SQLException {
		getUser(args[0]);
	}
	
	
	// SOURCE
	public static ResultSet getUser(String userId) throws SQLException {
		
		String query = "SELECT * FROM Users WHERE UserId = "+ userId;
		Connection c = DriverManager.getConnection(DB_URL, USER, PASS);
		
		// SINK
		ResultSet result = c.createStatement().executeQuery(query);
		return result;
		
	}
	

}
