// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 codstun contributors
// Targeted local network research. Exports remain in ignored research directories.
// @category CODSTUN
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class Inspect extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args[0]); out.mkdirs();
        Pattern pattern = Pattern.compile(args[1], Pattern.CASE_INSENSITIVE);
        TreeMap<String, Function> roots = new TreeMap<>();
        PrintWriter refs = new PrintWriter(new File(out, "references.txt"));
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data d = data.next();
            if (!d.hasStringValue() || d.getAddress().getOffset() >= 0x10000000) continue;
            String s = String.valueOf(d.getValue());
            if (!pattern.matcher(s).find()) continue;
            refs.println(d.getAddress() + " " + s);
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Reference r = ri.next(); Function f = getFunctionContaining(r.getFromAddress());
                refs.println("  " + r.getFromAddress() + " " + (f == null ? "?" : f.getName()));
                if (f != null) roots.put(f.getEntryPoint().toString(), f);
            }
        }
        for (int i=2; i<args.length; i++) {
            Function f = getFunctionContaining(toAddr(args[i]));
            if (f != null) roots.put(f.getEntryPoint().toString(), f);
        }
        TreeMap<String, Function> targets = new TreeMap<>(roots);
        for (Function f : roots.values()) {
            for (Function c : f.getCalledFunctions(monitor)) {
                long a=c.getEntryPoint().getOffset();
                if ((a>=0x238000 && a<0x270000) || (a>=0x398000 && a<0x3d0000))
                    targets.put(c.getEntryPoint().toString(), c);
            }
        }
        DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
        PrintWriter code = new PrintWriter(new File(out,"functions.c"));
        for (Function f : targets.values()) {
            code.println("\n// ADDRESS " + f.getEntryPoint() + " " + f.getName());
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            while (ri.hasNext()) {
                Reference r=ri.next(); Function caller=getFunctionContaining(r.getFromAddress());
                code.println("// XREF " + r.getFromAddress() + " " + (caller==null?"data":caller.getName()));
            }
            DecompileResults res=di.decompileFunction(f,45,monitor);
            if(res.decompileCompleted()) code.println(res.getDecompiledFunction().getC());
            else code.println("// ERROR " + res.getErrorMessage());
        }
        refs.close(); code.close(); di.dispose();
        println("Exported " + targets.size() + " functions");
    }
}
