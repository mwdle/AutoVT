package com.mwdle.autovt;

import com.codeborne.selenide.Condition;
import com.codeborne.selenide.Configuration;
import com.codeborne.selenide.Selenide;
import com.codeborne.selenide.SelenideElement;
import org.openqa.selenium.By;

import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.codeborne.selenide.Condition.*;
import static com.codeborne.selenide.Selectors.shadowCss;
import static com.codeborne.selenide.Selenide.*;

public class AutoVT {

    // TODO: Setup checks for community scores for uploads.
    // TODO: Don't allow uploading files larger than limit, and implement corresponding behavior for reports.
    // TODO: Move selectors into page object file.
    // TODO: Gracefully handle errors.
    // TODO: Add optional args for timeouts.
    // TODO: Switch args to env vars?

    public static final Duration REPORT_TIMEOUT = Duration.ofMinutes(8); // The maximum amount of time to wait for the file to upload, for the file to get scanned, and the report to load.

    public static final File currentDir = new File(System.getProperty("user.dir"));
    public static final File reportsDir = new File(currentDir, "AutoVT_Reports");
    public static final File screenshotsDir = new File(reportsDir, "screenshots");
    private static String detectionsReportFilepath;
    private static String cleanReportFilepath;

    public static void openVT() {
        open("https://www.virustotal.com/");
    }

    public static void login(String username, String password) {
        if (!username.isEmpty() && !password.isEmpty()) { // Only login if username and password are provided
            SelenideElement signInNavButton = $(shadowCss("div > a.signin", "body > vt-ui-shell", "uno-navbar", "div > div.hstack > uno-account-widget")).should(exist);
            checkForCaptcha();
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
    }

    public static void appendResultToReport(File file, String numberOfDetections) {
        String screenshotName = file.getName() + "_VT_screenshot";
        Selenide.screenshot(screenshotName);
        File screenshot = new File("screenshots", screenshotName + ".png");
        boolean isClean = numberOfDetections.equals("No");
        try (FileWriter reportFileWriter = new FileWriter(isClean ? cleanReportFilepath : detectionsReportFilepath, true)) {
            reportFileWriter.append(generateReportUploadResult(file.getName(), file.getAbsolutePath(), numberOfDetections.toLowerCase(), Selenide.webdriver().driver().url(), screenshot.getPath()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void collectResultsForReport(File file) {
        SelenideElement reportSummary = $(shadowCss("div > div.card-header > div.fw-bold", "#view-container > file-view", "#report > vt-ui-file-card")).should(exist, Duration.ofSeconds(10)); // Wait for the report to load
        String regex = "(No|\\d+\\/\\d+) security vendors? flagged this file as malicious$";
        Matcher match = Pattern.compile(regex).matcher(reportSummary.getText());
        if (!match.find()) throw new RuntimeException("Upload result not found.");
        appendResultToReport(file, match.group(1));
    }

    public static boolean checkForCaptcha() {
        Selenide.sleep(500); // Wait briefly before checking for the captcha
        SelenideElement captcha = $x("//*[contains(@id, 'captcha')]/*");
        boolean captchaWasPresent = captcha.exists();
        if (captchaWasPresent) {
            Toolkit.getDefaultToolkit().beep(); // Make a sound to notify the user that a captcha is required
            int timer = 0;
            while (captcha.exists()) {
                Selenide.sleep(1000);
                timer++;
                if (timer == 45) {
                    Toolkit.getDefaultToolkit().beep(); // Make a sound to remind the user about the captcha
                    timer = 0;
                }
            }
        }
        return captchaWasPresent;
    }

    public static void scanFilesAndGenerateReport(String dirPath) {
        SelenideElement uploadInput = $(shadowCss("#fileSelector", "#view-container > home-view", "#uploadForm")).should(exist);
        SelenideElement uploadButton = $(shadowCss("div > form > button", "#view-container > home-view", "#uploadForm"));
        File dir = new File(dirPath);
        File[] files = dir.listFiles();
        assert files != null;
        for (File file : files) {
            if (file.getName().startsWith("AutoVT")) continue;
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
                        currentTime = currentTime.plus(Duration.ofMillis(1500));
                        if (uploadInput.exists() && uploadButton.has(partialText("Choose file"))) { // Sometimes VT makes you reupload after captcha.
                            uploadInput.uploadFile(file);
                            Selenide.sleep(1500);
                            currentTime = currentTime.plus(Duration.ofMillis(1500));
                            if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();
                        }
                    } else {
                        Selenide.sleep(1000);
                        currentTime = currentTime.plus(Duration.ofSeconds(1));
                    }
                    if (currentTime.getSeconds() > 60 && (uploadButton.has(partialText("Checking hash")) || uploadButton.has(partialText("Choose file")))) { // If the page gets stuck, refresh and try again.
                        Selenide.refresh();
                        checkForCaptcha();
                        uploadInput.uploadFile(file);
                    }
                    if (currentTime.compareTo(REPORT_TIMEOUT) >= 0)
                        throw new RuntimeException("Report not found after " + REPORT_TIMEOUT.getSeconds() + " seconds."); // If the report is not found within the desired amount of time, throw an exception
                }

                collectResultsForReport(file);
                Selenide.open("https://www.virustotal.com/");
            }
        }
    }

    public static void initializeDirectories() {
        if (!reportsDir.exists() && !reportsDir.mkdirs()) {
            throw new RuntimeException("Failed to create reports directory: " + reportsDir);
        }
        if (!screenshotsDir.exists() && !screenshotsDir.mkdirs()) {
            throw new RuntimeException("Failed to create screenshots directory: " + screenshotsDir);
        }
        File downloadsDir = new File(reportsDir, "downloads");
        if (!downloadsDir.exists() && !downloadsDir.mkdirs()) {
            throw new RuntimeException("Failed to create downloads directory: " + downloadsDir);
        }
        Configuration.downloadsFolder = downloadsDir.getAbsolutePath(); // Setting this property is necessary to prevent selenide from creating a temporary directory with a random name. Selenide creating that is a problem because it persists if you exit the program early.
        Configuration.reportsFolder = screenshotsDir.getAbsolutePath();
        Configuration.savePageSource = false;
        Configuration.screenshots = false;
    }

    public static String generateReportUploadResult(String filename, String filepath, String numberOfDetections, String vtReportURL, String reportScreenshotFilepath) {
        try (InputStream inputStream = AutoVT.class.getResourceAsStream("/ReportUploadResultTemplate.html")) {
            return String.format(
                    new String(inputStream.readAllBytes()),
                    filename,
                    numberOfDetections.equals("no") ? "-no" : "",
                    numberOfDetections,
                    filepath,
                    filepath,
                    vtReportURL,
                    filename,
                    reportScreenshotFilepath
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateReportHeader(String filepath, String generationTime, boolean flaggedAsMalicious) {
        try (InputStream inputStream = AutoVT.class.getResourceAsStream("/ReportHeaderTemplate.html")) {
            return String.format(
                    new String(inputStream.readAllBytes()),
                    flaggedAsMalicious ? "Detections" : "Clean",
                    flaggedAsMalicious ? "were" : "were not",
                    filepath,
                    filepath,
                    generationTime
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void initializeReports(String dir) {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM dd, yyyy, hh:mm a");
        String nameOfFileToReportOn = (new File(dir)).getName();
        File detectionsReportFile = new File(reportsDir, nameOfFileToReportOn + "_detections_report_" + now.toLocalDate().toString() + ".html");
        detectionsReportFilepath = detectionsReportFile.getAbsolutePath();
        File cleanReportFile = new File(reportsDir, nameOfFileToReportOn + "_clean_report_" + now.toLocalDate().toString() + ".html");
        cleanReportFilepath = cleanReportFile.getAbsolutePath();
        try (FileWriter reportFileWriter = new FileWriter(detectionsReportFile, false)) {
            reportFileWriter.append(generateReportHeader(dir, now.format(formatter), true));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileWriter reportFileWriter = new FileWriter(cleanReportFile, false)) {
            reportFileWriter.append(generateReportHeader(dir, now.format(formatter), false));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void autoVT(String username, String password, String dir) {
        try {
            dir = new File(dir).getCanonicalPath(); // Handle symlinks and relative paths
        } catch (IOException ignored) {}
        initializeDirectories();
        initializeReports(dir);
        openVT();
        login(username, password);
        checkForCaptcha();
        scanFilesAndGenerateReport(dir);
    }

    public static void main(String[] args) {
        if (args.length == 3)
            autoVT(args[0], args[1], args[2]);
        else if (args.length == 1)
            autoVT("", "", args[0]);
        else {
            String dir;
            while (true) {
                System.out.println("Please enter the path to the directory you want to scan.");
                dir = new Scanner(System.in).nextLine();
                File file = new File(dir);
                if (file.isDirectory()) break;
                System.out.println("The path you entered is not a valid directory. Please try again.");
            }
            autoVT("", "", dir);
        }
    }
}