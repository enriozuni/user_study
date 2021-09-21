package example;

public class Main {

	public static void main(String[] args) {
		
		// SOURCE
		String tainted = source(args);
		
		String random = "randomValue";
		
		int intValue = 1;
		
		// SINK 1
		sink(tainted);
		
		// SINK 2
		sink(tainted, random);
		
		// SINK 3
		sink(tainted, random, intValue);
		
	}
	
	
	
	
	public static String source(String[] args) {
		if(args.length == 0) {
			return "is empty";
		}
		else {
			return "not empty";
		}
	}
	
	public static void sink(String param) {
		System.out.println(param);
	}
	
	public static void sink(String param1, String param2) {
		System.out.println(param1);
		System.out.println(param2);
	}
	
	public static void sink(String tainted, String random, int intValue) {
		System.out.println(tainted);
		System.out.println(random);
		System.out.println(intValue);
	}
	
}
