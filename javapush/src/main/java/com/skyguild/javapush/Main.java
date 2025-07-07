package com.skyguild.javapush;

//THIS IS A VERY RAW EXAMPLE OF HOW TO IMPLEMENT SERVER SIDE PUSH NOFITIFACTION
//ON A JAVA SERVER, WITHOUT DEALING WITH THE GOOGLE AUTH OR FIREBASE DEPENDENCIES.
//THIS CODE CAN EASILY BE PORTED TO OTHER LANGUAGES WITH IA
//AUTHOR: DHEX

import com.google.gson.Gson; //or change to your favorite map,Json encoder/decoder
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.net.HttpURLConnection;
import java.io.IOException;
import java.util.Map;

public class Main {

    //these come from the serviceaccountkey.json, will leave variables in worm format for clarity
    final String project_id = "*****";
    final String client_email = "firebase-adminsdk-fbsvc@*****.iam.gserviceaccount.com";
    final String private_key_id = "******";
    //please remove -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- from private_key
    final String private_key = "*****";

    String cachedAccessToken = "";
    long tokenExpirationTime = 0;
    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";

    public static void main(String[] args) {
        Main instance = new Main();
        instance.doPushNotification();
    }

    public void doPushNotification(){
        //you more likely send this via params
        String title = "New message";
        String message = "hello world";
        String extra = "extradata";
        String deviceToken = "***"; //this token arrives to each Android device on app launch. Pass it to the server
        new Thread(new sendPushNotificationRunnable(title, message, extra, deviceToken)).start();
    }

    class sendPushNotificationRunnable implements Runnable{
        String title, msg, extra, deviceToken;
        Gson gson = new Gson();

        public sendPushNotificationRunnable(String title, String msg, String extra, String deviceToken) {
            this.title = title;
            this.msg = msg;
            this.extra = extra;
            this.deviceToken = deviceToken;
        }

        public void run() throws RuntimeException {
            String accessToken = getAccessToken();
            sendNotification(accessToken);
        }

        public String getAccessToken(){
            //here we will ask Google Cloud for Firebase credentials, and return them as a String

            String newAccessToken = cachedAccessToken;
            long currentTimeSeconds = System.currentTimeMillis() / 1000;

            //if last token is still valid, we will skip all this and return the cached one
            if (cachedAccessToken.isEmpty() || currentTimeSeconds > tokenExpirationTime - 300) {

                String jwsKey;
                try{
                    Map<String, String> header = Map.of("alg", "RS256","typ", "JWT","kid", private_key_id);
                    byte[] bytes = gson.toJson(header).getBytes(StandardCharsets.UTF_8);
                    String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

                    Map<String, Object> claims = Map.of("iss", client_email,"sub", client_email,"aud", TOKEN_URI,
                            "iat", currentTimeSeconds,"exp", currentTimeSeconds + 3600,
                            "scope", "https://www.googleapis.com/auth/firebase.messaging");
                    bytes = gson.toJson(claims).getBytes(StandardCharsets.UTF_8);
                    String encodedClaims = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

                    String signingInput = encodedHeader + "." + encodedClaims;
                    String pemContent = private_key.replaceAll("\\s", "");

                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pemContent));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(keyFactory.generatePrivate(keySpec));
                    signature.update(signingInput.getBytes(StandardCharsets.UTF_8));


                    jwsKey = signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());


                } catch (Exception e) {
                    jwsKey = "";
                    System.err.println("Error generating JWT: " + e.getMessage());
                }

                if(!jwsKey.isEmpty()){
                    HttpURLConnection connection = null;

                    try {
                        URL url = new URL(TOKEN_URI);
                        String requestBody = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwsKey;
                        byte[] postData = requestBody.getBytes(StandardCharsets.UTF_8);

                        connection = (HttpURLConnection) url.openConnection();
                        connection.setRequestMethod("POST");
                        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                        connection.setDoOutput(true);
                        connection.setRequestProperty("Content-Length", String.valueOf(postData.length));

                        System.out.println("Sending token exchange request to " + TOKEN_URI + "...");

                        // Write the request body
                        try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                            wr.write(postData);
                            wr.flush();
                        }

                        int responseCode = connection.getResponseCode();
                        StringBuilder response = new StringBuilder();

                        // Read the response
                        try (BufferedReader in = new BufferedReader(
                                new InputStreamReader(
                                        (responseCode == HttpURLConnection.HTTP_OK) ? connection.getInputStream() : connection.getErrorStream(),
                                        StandardCharsets.UTF_8))) {
                            String inputLine;
                            while ((inputLine = in.readLine()) != null) {
                                response.append(inputLine);
                            }
                        }

                        String responseBody = response.toString();
                        if (responseCode == HttpURLConnection.HTTP_OK) {
                            Type typeOfHashMap = new TypeToken<Map<String, Object>>() {}.getType();
                            Map<String, Object> tokenResponseMap;
                            try {
                                tokenResponseMap = gson.fromJson(responseBody, typeOfHashMap);
                            } catch (JsonSyntaxException e) {
                                throw new IOException("Failed to parse token response JSON: " + e.getMessage() + "\nResponse: " + responseBody, e);
                            }

                            cachedAccessToken = (String) tokenResponseMap.get("access_token");
                            long expiresIn = ((Double)tokenResponseMap.get("expires_in")).longValue();
                            tokenExpirationTime = (System.currentTimeMillis() / 1000) + expiresIn;
                            System.out.println("Access Token obtained successfully. Expires in " + expiresIn + " seconds.");
                            newAccessToken = cachedAccessToken;
                        } else {
                            throw new IOException("Failed to get access token. Status: " + responseCode + ", Response: " + responseBody);
                        }
                    } catch (IOException e) {
                        System.out.println("Token error: " + e.getMessage());
                    } finally {
                        if (connection != null) {
                            connection.disconnect();
                        }
                    }
                }
            }
            return newAccessToken;
        }

        public void sendNotification(String accessToken){
            //Here we will finally access Firebase using the Google Access token,
            //and submit a payload with the notification
            String firebaseToken = getAccessToken();
            if (!firebaseToken.isEmpty()) {
                try {
                    URL url = new URL("https://fcm.googleapis.com/v1/projects/"+project_id+"/messages:send");
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json; UTF-8");
                    connection.setRequestProperty("Authorization", "Bearer " + accessToken);
                    connection.setUseCaches(false);
                    connection.setDoOutput(true);


                    if (!deviceToken.isEmpty()) {

                        Map<String, Object> finalPayload = Map.of(
                            "message", Map.of(
                                 "token", deviceToken,
                                "android", Map.of("priority", "HIGH"),
                                "data", Map.of("title", title,"body", msg,"extra", extra)
                            )
                        );
                        String jsonPayload = gson.toJson(finalPayload);

                        try (OutputStream os = connection.getOutputStream()) {
                            byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                            os.write(input, 0, input.length);
                        }

                        int responseCode = connection.getResponseCode();
                        if (responseCode == HttpURLConnection.HTTP_OK) {
                            System.out.println("Notification was send");
                        } else {
                            String errorResponse = new String(connection.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                            System.out.println("Notification error: " + errorResponse);
                        }
                    }
                    connection.disconnect();

                }catch(Exception e){
                    System.out.println("Notification error: " + e.getMessage());
                }
            }
        }
    }
}