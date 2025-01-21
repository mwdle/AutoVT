package com.mwdle.autovt;

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

    public static final Duration REPORT_TIMEOUT = Duration.ofMinutes(3); // The maximum amount of time to wait for the file to upload, for the file to get scanned, and the report to load.
    public static final Duration CAPTCHA_TIMEOUT = Duration.ofMinutes(20);

    public static final File currentDir = new File(System.getProperty("user.dir"));
    private static String detectionsReportFilepath;
    private static String cleanReportFilepath;

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
            Toolkit.getDefaultToolkit().beep(); // Make a sound to notify the user that multi-factor authentication is required
            $(By.id("code2fa")).shouldHave(Condition.attributeMatching("value", "^[0-9]{6}$"), Duration.ofMinutes(5)); // Wait for up to 5 minutes for the user to enter the authentication code
            $(By.id("sign-in-btn")).shouldBe(interactable).click();
        }
    }

    public static void appendResultToReport(File file, String numberOfDetections) {
        String base64Screenshot = Base64.getEncoder().encodeToString(Selenide.screenshot(OutputType.BYTES));
        boolean isClean = numberOfDetections.equals("No");
        try (FileWriter reportFileWriter = new FileWriter(isClean ? cleanReportFilepath : detectionsReportFilepath, true)) {
            String pathOfFileToReport = file.getAbsolutePath();
            reportFileWriter.append("---\n\n### ").append(file.getName()).append("\n")
                    .append("There were ").append(numberOfDetections.toLowerCase()).append(" detections for: [").append(pathOfFileToReport).append("](</").append(pathOfFileToReport).append(">)\n\n")
                    .append("[View Report](").append(Selenide.webdriver().driver().url()).append(")\n")
                    .append("![Screenshot of the report](").append("data:image/png;base64,").append(base64Screenshot).append(")\n\n");
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void collectResultsForReport(File file) {
        SelenideElement reportSummary = $(shadowCss("div > div.card-header > div.fw-bold", "#view-container > file-view", "#report > vt-ui-file-card")).should(exist, Duration.ofSeconds(10)); // Wait for the report to load
        String regex = "(No|\\d+\\/\\d+) security vendors flagged this file as malicious$";
        Matcher match = Pattern.compile(regex).matcher(reportSummary.getText());
        if (!match.find()) throw new RuntimeException("Upload result not found.");
        appendResultToReport(file, match.group(1));
    }

    public static boolean checkForCaptcha() {
        SelenideElement captcha = $x("//*[contains(@id, 'captcha')]/*");
        boolean captchaPresent = captcha.exists();
        if (captchaPresent) {
            Toolkit.getDefaultToolkit().beep(); // Make a sound to notify the user that a captcha is required
            captcha.shouldNot(exist, CAPTCHA_TIMEOUT); // Wait for the desired amount of time or until the user enters the captcha
        }
        return captchaPresent;
    }

    public static void scanFilesAndGenerateReport(String dirPath) {
        SelenideElement uploadInput = $(shadowCss("#fileSelector", "#view-container > home-view", "#uploadForm")).should(exist);
        SelenideElement uploadButton = $(shadowCss("div > form > button", "#view-container > home-view", "#uploadForm"));
        File dir = new File(dirPath);
        File[] files = dir.listFiles();
        assert files != null;
        for (File file : files) {
            if (file.isDirectory()) {
                scanFilesAndGenerateReport(file.getAbsolutePath());
            } else {
                uploadInput.uploadFile(file);
                Selenide.sleep(1500);
                if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();

                SelenideElement report = $(shadowCss("#report", "#view-container > file-view"));

                Duration currentTime = Duration.ZERO;

                while (!report.exists()) {
                    if (checkForCaptcha()) {
                        Selenide.sleep(1500);
                        currentTime.plus(Duration.ofMillis(1500));
                        if (uploadInput.exists()) { // Sometimes VT makes you reupload after captcha.
                            uploadInput.uploadFile(file);
                            Selenide.sleep(1500);
                            currentTime.plus(Duration.ofMillis(1500));
                            if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();
                        }
                    }
                    else {
                        Selenide.sleep(1000);
                        currentTime.plus(Duration.ofSeconds(1));
                    }
                    if (currentTime.compareTo(REPORT_TIMEOUT) >= 0) throw new RuntimeException("Report not found after " + REPORT_TIMEOUT.getSeconds() + " seconds."); // If the report is not found within the desired amount of time, throw an exception
                }

                collectResultsForReport(file);
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
            reportFileWriter.append("# Virus Total Report\n**This is a Virus Total report for all files that were flagged as malicious from the directory:** [").append(dir).append("](</").append(dir).append(">)\n\n*This report was created on: ").append(today).append("*\n\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileWriter reportFileWriter = new FileWriter(cleanReportFile, false)) {
            reportFileWriter.append("# Virus Total Report\n**This is a Virus Total report for all files that were not flagged by any security vendors from the directory:** [").append(dir).append("](</").append(dir).append(">)\n\n*This report was created on: ").append(today).append("*\n\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void scanFiles(String username, String password, String dir) {
        initializeReports(dir);
        openVT();
        login(username, password);
        scanFilesAndGenerateReport(dir);
    }

    public static void main(String[] args) {
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