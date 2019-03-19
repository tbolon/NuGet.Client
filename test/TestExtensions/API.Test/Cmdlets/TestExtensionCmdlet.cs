// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Management.Automation;
using System.Threading;
using Microsoft;
using Microsoft.VisualStudio.Shell;
using Task = System.Threading.Tasks.Task;

namespace API.Test.Cmdlets
{
    public abstract class TestExtensionCmdlet : Cmdlet
    {
        private readonly Lazy<int> _threadId = new Lazy<int>(() => System.Threading.Thread.CurrentThread.ManagedThreadId);

        public string CmdletName { get; }

        protected TestExtensionCmdlet()
        {
            var attribute = Attribute.GetCustomAttribute(GetType(), typeof(CmdletAttribute), inherit: true) as CmdletAttribute;
            Assumes.NotNull(attribute);
            CmdletName = $"{attribute.VerbName}-{attribute.NounName}";
        }

        protected override void ProcessRecord()
        {
            AssertCorrectThread();

            ThreadHelper.JoinableTaskFactory.Run(() => ProcessRecordAsync());
        }

        protected override void BeginProcessing()
        {
            TracedWriteVerbose($"{CmdletName}: Begin");

            base.BeginProcessing();
        }

        protected override void EndProcessing()
        {
            TracedWriteVerbose($"{CmdletName}: End");

            base.EndProcessing();
        }

        protected override void StopProcessing()
        {
            TracedWriteVerbose($"{CmdletName}: Stop ({_threadId.Value})");

            base.StopProcessing();
        }

        protected abstract Task ProcessRecordAsync();

        protected void TracedWriteObject(object sendToPipeline, bool enumerateCollection)
        {
            AssertCorrectThread();

            base.WriteObject(sendToPipeline, enumerateCollection);
        }

        protected void TracedWriteObject(object sendToPipeline)
        {
            AssertCorrectThread();

            base.WriteObject(sendToPipeline);
        }

        protected void TracedWriteVerbose(string text)
        {
            AssertCorrectThread();

            base.WriteVerbose(text);
        }

        protected void AssertCorrectThread()
        {
            var currentThreadId = System.Threading.Thread.CurrentThread.ManagedThreadId;

            if (currentThreadId != _threadId.Value)
            {
                throw new InvalidOperationException($"WriteObject(...) or WriteError(...) called on wrong thread.");
            }
        }
    }
}
