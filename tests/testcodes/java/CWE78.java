import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

public class CWE78 {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String userInput = br.readLine();
        String command = "ping -c 1 " + userInput;
        System.out.println("Executing command: " + command);
        Runtime.getRuntime().exec(command);
    }
}