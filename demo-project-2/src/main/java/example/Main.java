package example;

public class Main {

	public static void main(String[] args) {
		
		// SOURCE
		String tainted = source(args);
		
		String strValue = "string value";
		
		int intValue = 1;
		
		// SINK 1
		sink(tainted);
		
		// SINK 2
		sink(tainted, strValue);
		
		// SINK 3
		sink(tainted, strValue, intValue);
		
	}
	
	public static String source(String[] args) {
		if(args.length == 0) {
			return "is empty";
		}
		else {
			return "not empty";
		}
	}
	
	public static void sink(String param1) {
		System.out.println(param1);
	}
	
	public static void sink(String param1, String param2) {
		System.out.println(param1);
		System.out.println(param2);
	}
	
	public static void sink(String param1, String param2, int param3) {
		System.out.println(param1);
		System.out.println(param2);
		System.out.println(param3);
	}
	
}
