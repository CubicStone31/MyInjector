## MyInjector

MyInjector is a dll injection tool, to force a program to load your dll module.

![image](https://user-images.githubusercontent.com/90182934/148061599-d7604c54-ccf7-49c8-9383-f427da3c6ea5.png)

The UI should be quite self-explainary. You can select your injection target process by "drag and drop" a finder to the target's windows, just like the following

![e6ZJ54ByN4](https://user-images.githubusercontent.com/90182934/148766791-173f7c3a-9b86-411d-9564-b56b94f79d55.gif)

Then you select the injection method and click 'confirm'

![z2Lio6Wwja](https://user-images.githubusercontent.com/90182934/148767329-e145e744-6b81-4301-832d-1770f0fbf3df.gif)

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

To use kernel mode injection methods, you should place *KernelCorridor.sys* under this tool's directory. *KernelCorridor.sys* can be found at here(https://github.com/CubicStone31/KernelCorridor).

## Why another dll injector?

I make this project just for fun, for learning .Net GUI development and for practicing many known dll inject technology.
