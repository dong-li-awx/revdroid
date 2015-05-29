package com.lazarusx.revdroid.analyzer;

import java.io.IOException;

import org.xmlpull.v1.XmlPullParserException;

public class Main {
	final static String ANDROID_PLATFORM_PATH = "/home/ray/android-sdk/platforms";
	final static String PSCOUT_RESULT_PATH = "/home/ray/pscout/results/jellybean_allmappings";
	
	final static boolean DEBUG = false;

	public static void main(String[] args) {
		String apkPath = args[0];
		Application app = null;
		try {
			app = new Application(ANDROID_PLATFORM_PATH, apkPath, PSCOUT_RESULT_PATH);
		} catch (IOException | XmlPullParserException e) {
			e.printStackTrace();
		}
		
		if (DEBUG) {
			app.printEntryPoints();
			app.printMethodsConcerned();
		}
		
		if (app != null) {
			Analyzer analyzer = new Analyzer(app);
			analyzer.analyze();
		}
	}

}
