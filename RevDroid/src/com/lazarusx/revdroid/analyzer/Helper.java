package com.lazarusx.revdroid.analyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;

import soot.G;

public class Helper {
	public static void printDebugMessage(String message) {
		if (Main.DEBUG) {
			System.out.println(message);
		}
	}
	
	public static void setOutput() {
		if (!Main.DEBUG) {
			try {
				G.v().out = new PrintStream(new File("/dev/null"));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} 
		}
	}
}
