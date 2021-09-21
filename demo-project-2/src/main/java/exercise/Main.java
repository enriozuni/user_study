package exercise;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Random;

public class Main {

	static final String DB_URL = "168.192.0.1";
	static final String USER = "guest";
	static final String PASS = "pass123";
	
	public static void main(String[] args) throws SQLException {
		updateAccount(args[0]);
	}
	
	// SOURCE
	public static void updateAccount(String customerId) throws SQLException {
		String query = " UPDATE people SET name =' John ' where id = ' "
				+ customerId
				+ "'";
		Connection c = DriverManager.getConnection(DB_URL, USER, PASS);
		
		if(customerId.length() == 10) {
			// SINK 1
			c.createStatement().executeUpdate(query);
		}
		
		else if(customerId.length() == 11) {
			Random random = new Random();
			// SINK 2
			c.createStatement().executeUpdate(query, random.nextInt(10));
		}
		
		else if(customerId.length() == 12) {
			// SINK 3
			c.createStatement().executeUpdate(query, new int[]{ 1,2,3,4,5,6,7,8,9,10 });
		}
		
		else {
			System.out.println("Cannot update the customer ID.");
		}
	}
	

}
