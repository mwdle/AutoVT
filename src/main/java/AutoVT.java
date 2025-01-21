import com.codeborne.selenide.Condition;
import com.codeborne.selenide.Configuration;
import com.codeborne.selenide.Selenide;
import com.codeborne.selenide.SelenideElement;
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.chrome.ChromeOptions;

import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.codeborne.selenide.Condition.*;
import static com.codeborne.selenide.Selenide.*;
import static com.codeborne.selenide.Selectors.shadowCss;

public class AutoVT {

    // TODO: Setup checks for community scores for uploads.

    public static Duration UPLOAD_TIMEOUT = Duration.ofMinutes(2);
    public static Duration REPORT_TIMEOUT = Duration.ofSeconds(90);
    public static Duration CAPTCHA_TIMEOUT = Duration.ofMinutes(10);

    public static final File currentDir = new File(System.getProperty("user.dir"));
    public static String detectionsReportFilepath;
    public static String cleanReportFilepath;

    public static void openVT() {
        open("https://www.virustotal.com/");
    }

    public static void login(String username, String password) {
        SelenideElement signInNavButton =  $(shadowCss("div > a.signin", "body > vt-ui-shell", "uno-navbar", "div > div.hstack > uno-account-widget")).should(exist);
        signInNavButton.click();
        $(By.id("userId")).shouldBe(interactable).setValue(username);
        $(By.id("password")).shouldBe(interactable).setValue(password);
        $x("//input[contains(@type, 'checkbox')]").shouldBe(interactable).setSelected(true);
        $(By.id("sign-in-btn")).shouldBe(interactable).click();
        Selenide.sleep(1500); // Wait for the page to load to determine if multi-factor authentication is required
        SelenideElement multiFactorAuth = $x("//*[contains(text(), 'Authentication code')]");
        if (multiFactorAuth.isDisplayed()) {
            Toolkit.getDefaultToolkit().beep();
            $(By.id("code2fa")).shouldHave(Condition.attributeMatching("value", "^[0-9]{6}$"), Duration.ofMinutes(5)); // Wait for up to 5 minutes for the user to enter the authentication code
            $(By.id("sign-in-btn")).shouldBe(interactable).click();
        }
    }

    public static void appendResultToReport(String filename, String numberOfDetections) {
        String base64Screenshot = Base64.getEncoder().encodeToString(Selenide.screenshot(OutputType.BYTES));
        boolean isClean = numberOfDetections.equals("No");
        try (FileWriter reportFileWriter = new FileWriter(isClean ? cleanReportFilepath : detectionsReportFilepath, true)) {
            reportFileWriter.append("---\n\n### ").append(filename).append("\n")
                    .append("There were ").append(numberOfDetections.toLowerCase()).append(" detections for: `").append(filename).append("`\n\n")
                    .append("[View Report](").append(Selenide.webdriver().driver().url()).append(")\n")
                    .append("![Screenshot of the report](").append("data:image/png;base64,").append(base64Screenshot).append(")\n\n");
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void checkForMaliciousResult(String filename) {
        SelenideElement reportSummary = $(shadowCss("div > div.card-header > div.fw-bold", "#view-container > file-view", "#report > vt-ui-file-card")).should(exist, Duration.ofSeconds(10)); // Wait for the report to load
        String regex = "(No|\\d+\\/\\d+) security vendors flagged this file as malicious$";
        Matcher match = Pattern.compile(regex).matcher(reportSummary.getText());
        if (!match.find()) throw new RuntimeException("Upload result not found.");
        appendResultToReport(filename, match.group(1));
    }

    public static boolean checkForCaptcha() {
        Selenide.sleep(1250);
        SelenideElement captcha = $x("//*[contains(@id, 'captcha')]/*");
        boolean hasCaptcha = captcha.isDisplayed();
        if (hasCaptcha) {
            Toolkit.getDefaultToolkit().beep();
            captcha.shouldNot(exist, CAPTCHA_TIMEOUT);
        }
        return hasCaptcha;
    }

    public static void uploadFiles(String dirPath) {
        SelenideElement uploadInput = $(shadowCss("#fileSelector", "#view-container > home-view", "#uploadForm")).should(exist);
        SelenideElement uploadButton = $(shadowCss("div > form > button", "#view-container > home-view", "#uploadForm"));
        File dir = new File(dirPath);
        File[] files = dir.listFiles();
        assert files != null;
        for (File file : files) {
            if (file.isDirectory()) {
                uploadFiles(file.getAbsolutePath());
            } else {
                uploadInput.uploadFile(file);
                Selenide.sleep(1500);
                if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();
                if (checkForCaptcha()) {
                    Selenide.sleep(1500);
                    if (uploadInput.exists()) {
                        uploadInput.uploadFile(file);
                        Selenide.sleep(1500);
                        if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();
                    }
                }
                uploadButton.shouldNot(exist, UPLOAD_TIMEOUT);
                $(shadowCss("#report", "#view-container > file-view")).should(exist, REPORT_TIMEOUT); // Wait for the report to generate
                checkForMaliciousResult(file.getName());
                Selenide.open("https://www.virustotal.com/");
            }
        }
    }

    public static void initializeReports(String dir) {
        String today = LocalDate.now().toString();
        File detectionsReportFile = new File(currentDir.toString().replace(' ', '_'), (new File(dir)).getName() + "_detections_report_" + today + ".md");
        detectionsReportFilepath = detectionsReportFile.getPath();
        File cleanReportFile = new File(currentDir.toString().replace(' ', '_'), (new File(dir)).getName() + "_clean_report_" + today + ".md");
        cleanReportFilepath = cleanReportFile.getPath();
        try (FileWriter reportFileWriter = new FileWriter(detectionsReportFile, false)) {
            reportFileWriter.append("# Virus Total Report\n**This is a Virus Total report for all files that were flagged as malicious from the directory:** `").append(dir).append("`\n\n*This report was created on: ").append(today).append("*\n\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileWriter reportFileWriter = new FileWriter(cleanReportFile, false)) {
            reportFileWriter.append("# Virus Total Report\n**This is a Virus Total report for all files that were not flagged by any security vendors from the directory:** `").append(dir).append("`\n\n*This report was created on: ").append(today).append("*\n\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void scanFiles(String username, String password, String dir) {
        initializeReports(dir);
        openVT();
        login(username, password);
        uploadFiles(dir);
    }

    public static void main(String[] args) {
        // Configure Chrome
        ChromeOptions chromeOptions = new ChromeOptions();
//        chromeOptions.addArguments("--incognito", "--headless", "--no-sandbox", "--disable-gpu", "--start-maximized", "--window-size=1920,1080");
        Configuration.browserCapabilities = chromeOptions;
        // Handle input arguments
        if (args.length == 3)
            scanFiles(args[0], args[1], args[2]);
        else {
            System.out.println("Invalid number of arguments.");
            System.out.println("Usage: java AutoVT <username> <password> <dir>");
            System.exit(1);
        }
    }
}
