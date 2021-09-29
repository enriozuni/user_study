package example;

public class Main {

	public static void main(String[] args) {
		
		// SOURCE
		String tainted1 = source(args);
		
		String tainted2 = tainted1;
		
		String tainted3 = tainted2;
		
		// SINK
		sink(tainted3);
		
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
	
}
