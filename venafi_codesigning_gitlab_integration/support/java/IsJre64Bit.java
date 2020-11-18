public class IsJre64Bit {
	public static void main(String[] args) {
		if (System.getProperty("os.arch").equals("x86")) {
			System.out.println("false");
		} else {
			System.out.println("true");
		}
	}
}
