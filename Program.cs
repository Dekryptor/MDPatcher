using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;

namespace MDPatcher;

class Program {
 
    private static ModuleDefinition LoadModule(string path) {
        byte[] data = File.ReadAllBytes(path);
        ModuleDefinition module = ModuleDefinition.FromBytes(data);
        return module;
    }

    private static void AddPermissions(string path) {
#if OS_WINDOWS
        string currentUser = Environment.UserName;
        FileInfo fileInfo = new FileInfo(path);

        FileSecurity fileSecurity = fileInfo.GetAccessControl();

        FileSystemAccessRule accessRule = new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            AccessControlType.Allow
        );

        fileSecurity.AddAccessRule(accessRule);
        
        fileInfo.SetAccessControl(fileSecurity);
#endif
    }

    private static void ReturnBooleanFor(CilMethodBody body, bool value) {
        body.Instructions.Add(new CilInstruction(value ? CilOpCodes.Ldc_I4_1 : CilOpCodes.Ldc_I4_0));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
    }

    private static void ReturnNullFor(CilMethodBody body) {
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldnull));
        body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
    }

    private static void ReturnStringFor(CilMethodBody body, string value) {
        body.Instructions.Add(CilOpCodes.Ldstr, value);
        body.Instructions.Add(CilOpCodes.Ret);
    }

    private static void CreateBody(CilMethodBody body) {
        body.ExceptionHandlers.Clear();
        body.Instructions.Clear();
        body.LocalVariables.Clear();
    }

    private static void RemoveLineNumbers(MethodDefinition definition) {
        foreach (CustomAttribute attribute in definition.CustomAttributes.Where(
            a => a.Constructor != null && a.Constructor.FullName.Contains("LineNumberTableAttribute")
        ).ToList()) {
            definition.CustomAttributes.Remove(attribute);
        }
    }

    private static void EmptyBodyFor(MethodDefinition method) {
        CilMethodBody? body = method.CilMethodBody;

        if (body == null) {
            return;
        }

        RemoveLineNumbers(method);
        CreateBody(body);
        
        if (method.Signature == null) {
            return;
        }

        switch (method.Signature.ReturnType.FullName) {
            case "System.String":
                ReturnStringFor(body, "");
                break;
            case "System.Boolean":
                ReturnBooleanFor(body, true);
                break;
            case "java.util.concurrent.Future":
                ReturnNullFor(body);
                break;
            case "System.Void":
                break;
            default:
                throw new Exception($"Unexpected type for {method.FullName}: {method.Signature.ReturnType.FullName}");
        }
    }
    
    private static CilInstructionLabel AddGetValueMethodCase(ModuleDefinition module, CilMethodBody body, string key, string value, CilInstructionLabel? previous) {
        var caseLabel = new CilInstructionLabel();
        var beginning = new CilInstruction(CilOpCodes.Ldarg_1);
        
        if (previous != null) {
            previous.Instruction = beginning;
        }

        var stringEqualsMethod = module.DefaultImporter.ImportMethod(typeof(string).GetMethod("Equals", new[] { typeof(string) })!);

        body.Instructions.Add(beginning);
        body.Instructions.Add(CilOpCodes.Ldstr, key);
        body.Instructions.Add(CilOpCodes.Call, stringEqualsMethod);
        body.Instructions.Add(CilOpCodes.Brfalse, caseLabel);
        ReturnStringFor(body, value);

        return caseLabel;
    }

    private static void PatchLicenseFactory(TypeDefinition targetType, MethodDefinition licenseConstructor, MemberReference singletonList) {
        foreach (MethodDefinition targetMethod in targetType.Methods.Where(m => m.Name == "verify" || m.Name == "accept")) {
            EmptyBodyFor(targetMethod);
        }

        foreach (MethodDefinition targetMethod in targetType.Methods.Where(m => m.Signature?.ReturnType.Name == "License" && m.CilMethodBody != null)) {
            var body = targetMethod.CilMethodBody!;
            
            RemoveLineNumbers(targetMethod);
            CreateBody(body);
            
            // Create the new license
            body.Instructions.Add(CilOpCodes.Newobj, licenseConstructor);
            body.Instructions.Add(CilOpCodes.Ret);
        }

        foreach (MethodDefinition targetMethod in targetType.Methods.Where(m => m.Signature?.ReturnType.FullName == "java.util.List" && m.CilMethodBody != null)) {
            var body = targetMethod.CilMethodBody!;
            
            RemoveLineNumbers(targetMethod);
            CreateBody(body);
            
            // Create a new list containing the license
            body.Instructions.Add(CilOpCodes.Newobj, licenseConstructor);
            body.Instructions.Add(CilOpCodes.Call, singletonList);
            body.Instructions.Add(CilOpCodes.Ret);
        }

        // Recursively patch nested types as well
        foreach (TypeDefinition type in targetType.NestedTypes) {
            PatchLicenseFactory(type, licenseConstructor, singletonList);
        }
    }

    private static void WaitForKey() {
        Console.WriteLine("Press any key to continue...");
        Console.Read();
    }

    static int Main() {
        // Get the path to the "Program Files" folder
        string programFilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        // Append the "Mountain Duck" folder name to the path
        string mountainDuckPath = Path.Combine(programFilesPath, "Mountain Duck");

        string duckExePath = Path.Combine(mountainDuckPath, "Mountain Duck.exe");
        string duckCorePath = Path.Combine(mountainDuckPath, "Mountainduck.Core.dll");
        string cyberDuckCorePath = Path.Combine(mountainDuckPath, "Cyberduck.Core.dll");

        if (!File.Exists(duckExePath)) {
            Console.WriteLine($"{duckExePath} is missing!");
            WaitForKey();
            return 1;

        }
        if (!File.Exists(duckCorePath)) {
            Console.WriteLine($"{duckCorePath} is missing!");
            WaitForKey();
            return 1;
        }

        if (!File.Exists(cyberDuckCorePath)) {
            Console.WriteLine($"{cyberDuckCorePath} is missing!");
            WaitForKey();
            return 1;
        }

        AddPermissions(cyberDuckCorePath);

        ModuleDefinition cyberDuckCore = LoadModule(cyberDuckCorePath);

        // Is Mountain Duck already patched?
        if (cyberDuckCore.TopLevelTypes.Any(m => m.FullName == "ch.cyberduck.core.aquaticprime.LegitLicense")) {
            Console.WriteLine("Already patched.");
            WaitForKey();
            return 0;
        }

        AddPermissions(duckExePath);
        AddPermissions(duckCorePath);

        ModuleDefinition duckCore = LoadModule(duckCorePath);

        // Patch Mountain Duck license verification
        foreach (TypeDefinition targetType in duckCore.TopLevelTypes.Where(m => m.Namespace == "ch.iterate.mountainduck.registration")) {
            foreach (MethodDefinition targetMethod in targetType.Methods.Where(m => m.Name == "verify")) {
                EmptyBodyFor(targetMethod);
            }
        }

        // Patch MAC service
        try {
            TypeDefinition macService = duckCore.TopLevelTypes.Single(m => m.FullName == "ch.iterate.mountainduck.registration.MacUniqueIdService");
            MethodDefinition enumerateMethod = macService.Methods.Single(m => m.Name == "enumerate");
            MethodDefinition uuidMethod = macService.Methods.Single(m => m.Name == "getUUID");
            EmptyBodyFor(enumerateMethod);
            EmptyBodyFor(uuidMethod);
        } catch {
            Console.WriteLine("Unique ID service is not part of this version.");
        }

        // Remove trial service key download
        TypeDefinition trialService = duckCore.TopLevelTypes.Single(m => m.FullName == "ch.iterate.mountainduck.registration.TrialKeyLicenseService");
        MethodDefinition downloadMethod = trialService.Methods.Single(m => m.Name == "download");
        MethodDefinition installMethod = trialService.Methods.Single(m => m.Name == "install");

        EmptyBodyFor(downloadMethod);
        EmptyBodyFor(installMethod);

        // Patch Cyber Duck license verification
        foreach (TypeDefinition targetType in cyberDuckCore.TopLevelTypes.Where(m => m.Namespace == "ch.cyberduck.core.aquaticprime")) {
            foreach (MethodDefinition targetMethod in targetType.Methods.Where(m => m.Name == "verify" || m.Name == "accept")) {
                EmptyBodyFor(targetMethod);
            }
        }

        MemberReference singletonList = cyberDuckCore.GetImportedMemberReferences().Single(m => m.Name == "singletonList");
        MemberReference javaObjectConstructor = cyberDuckCore.GetImportedMemberReferences().Single(m => m.FullName == "System.Void java.lang.Object::.ctor()");
        TypeReference javaObject = cyberDuckCore.GetImportedTypeReferences().Single(m => m.FullName == "java.lang.Object");

        TypeDefinition licenseType = cyberDuckCore.TopLevelTypes.First(t => t.FullName == "ch.cyberduck.core.aquaticprime.License");
        TypeDefinition legitLicense = new TypeDefinition("ch.cyberduck.core.aquaticprime", "LegitLicense", TypeAttributes.Public | TypeAttributes.Class)
        {
            BaseType = javaObject
        };

        legitLicense.Interfaces.Add(new InterfaceImplementation(licenseType));
        cyberDuckCore.TopLevelTypes.Add(legitLicense);

        MethodAttributes overrideAttr = MethodAttributes.Public | MethodAttributes.NewSlot | MethodAttributes.HideBySig | MethodAttributes.Final | MethodAttributes.Virtual;
        MethodAttributes toStringAttr = MethodAttributes.Public | MethodAttributes.CheckAccessOnOverride | MethodAttributes.HideBySig | MethodAttributes.Virtual;
        MethodAttributes constructorAttr =MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName;

        // Add the getValue method
        var actualGetValueMethod = licenseType.Methods.Single(m => m.Name == "getValue");
        var getValueMethod = new MethodDefinition("getValue", overrideAttr, actualGetValueMethod.Signature) {
            ImplAttributes = actualGetValueMethod.ImplAttributes
        };

        // Create the CIL body for getValue method
        var getValueBody = new CilMethodBody(getValueMethod);

        // Add cases for different 'key' values
        CilInstructionLabel previous;
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Email", "admin@example.com", null);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Expiry", "2040-12-31T00:00:00.000000", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Installations", "1", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Name", "Full Version", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Product", "Mountain Duck", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Timestamp", "2000-01-01T00:00:00.000000", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Transaction", "45ca953e-ff56-4313-867c-aba13c8d26c9", previous);
        previous = AddGetValueMethodCase(cyberDuckCore, getValueBody, "Version", "4", previous);

        // Add the default case
        var nextCase = new CilInstruction(CilOpCodes.Ldstr, "");
        previous.Instruction = nextCase;

        getValueBody.Instructions.Add(nextCase);
        getValueBody.Instructions.Add(CilOpCodes.Ret); // Return
        getValueMethod.CilMethodBody = getValueBody;

        // Add the getName method
        var actualGetNameMethod = licenseType.Methods.Single(m => m.Name == "getName");
        var getNameMethod = new MethodDefinition("getName", overrideAttr, actualGetNameMethod.Signature)
        {
            ImplAttributes = actualGetNameMethod.ImplAttributes
        };
        
        // Create the CIL body for getName method
        var getNameBody = new CilMethodBody(getNameMethod);
        ReturnStringFor(getNameBody, "Admin");
        getNameMethod.MethodBody = getNameBody;

        // Add the toString method
        List<TypeSignature> toStringReturnSignature = new List<TypeSignature>();
        MethodSignature toStringSignature = new MethodSignature(CallingConventionAttributes.HasThis, cyberDuckCore.CorLibTypeFactory.String, toStringReturnSignature);
        var toStringMethod = new MethodDefinition("toString", toStringAttr, toStringSignature);

        // Create the CIL body for getName method
        var toStringBody = new CilMethodBody(getNameMethod);
        ReturnStringFor(toStringBody, "Registered to Admin");
        toStringMethod.MethodBody = toStringBody;

        // Add the isReceipt method
        var actualIsReceiptMethod = licenseType.Methods.First(m => m.Name == "isReceipt");
        var isReceiptMethod = new MethodDefinition("isReceipt",
            overrideAttr, actualIsReceiptMethod.Signature)
        {
            ImplAttributes = actualIsReceiptMethod.ImplAttributes
        };

        // Create the CIL body for getName method
        var isReceiptBody = new CilMethodBody(isReceiptMethod);
        ReturnBooleanFor(isReceiptBody, false);
        isReceiptMethod.MethodBody = isReceiptBody;

        // Add the verify method
        var actualVerifyMethod = licenseType.Methods.First(m => m.Name == "verify");
        var verifyMethod = new MethodDefinition("verify", overrideAttr, actualVerifyMethod.Signature)
        {
            ImplAttributes = actualVerifyMethod.ImplAttributes
        };
        
        // Create the CIL body for verify method
        var verifyBody = new CilMethodBody(verifyMethod);
        ReturnBooleanFor(verifyBody, true);
        verifyMethod.MethodBody = verifyBody;

        // Create empty constructor
        MethodSignature emptyConstructor = new MethodSignature(CallingConventionAttributes.HasThis, cyberDuckCore.CorLibTypeFactory.Void, new List<TypeSignature>());
        MethodDefinition emptyConstructorMethod = new MethodDefinition(".ctor", constructorAttr, emptyConstructor);

        // Create a constructor body that returns without doing anything.
        var emptyBody = new CilMethodBody(emptyConstructorMethod);
        emptyBody.Instructions.Add(CilOpCodes.Ldarg_0);
        emptyBody.Instructions.Add(CilOpCodes.Call, javaObjectConstructor);
        emptyBody.Instructions.Add(CilOpCodes.Ret);
        emptyConstructorMethod.CilMethodBody = emptyBody;

        // Add methods
        legitLicense.Methods.Add(emptyConstructorMethod);
        legitLicense.Methods.Add(verifyMethod);
        legitLicense.Methods.Add(getValueMethod);
        legitLicense.Methods.Add(getNameMethod);
        legitLicense.Methods.Add(isReceiptMethod);
        legitLicense.Methods.Add(toStringMethod);

        // Patch Mountain Duck license verification
        foreach (TypeDefinition targetType in cyberDuckCore.TopLevelTypes.Where(m => m.Namespace == "ch.cyberduck.core.aquaticprime")) {
            PatchLicenseFactory(targetType, emptyConstructorMethod, singletonList);
        }

        // Write the assemblies.
        duckCore.Write(duckCorePath);
        cyberDuckCore.Write(cyberDuckCorePath);

        Console.WriteLine("Patching successful!");
        WaitForKey();
        return 0;
    }
}
