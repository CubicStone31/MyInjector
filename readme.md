## MyInjector

MyInjector is a dll injection tool, to force a program to load your dll module.

![image](https://user-images.githubusercontent.com/90182934/148061599-d7604c54-ccf7-49c8-9383-f427da3c6ea5.png)

The UI should be quite self-explainary. Also, you can select your injection target process by "drag and drop" a finder to the target's windows, just like the following

## Implemented Injection Methods

We break the injection procedure into serveral "parts", and each part has a few selection of methods. For example, to access your target process, you can choose:

+ Legitimate windows API, such as OpenProcess() and WriteProcessMemory()
+ Duplicating a existing handle to your target
+ Using a kernel module's assistant

Once you have the accesss to your target, you can gain a chance of code execution under your target's context, by one of the following means:

+ Using API CreateRemoteThread()
+ Using API QueueUserAPC()
+ Using a internal Windows machenism, Process Instrument Callback

And when your code get a chance of execution, your code's entry point could be one of the followings:

+ LoadLibrary()
+ LDRLoadDLL()
+ A piece of shellcode to load your dll manaully, without the OS's assistance

You can combine these injection "parts" to build your own injection methods.

Currrently, a few injection options listed in the software's UI are still under constrcution. However, they should be implemeted in the near future.

When using kernel mode injection methods, your should load my kernel assistance module, which is another project of mine, KernelCorridor(https://github.com/CubicStone31/KernelCorridor).

## Why another dll injector?

I make this project just for fun, for learning .Net GUI development and for practicing many known dll inject technology.
