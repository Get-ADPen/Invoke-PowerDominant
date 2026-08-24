Get-ScheduledTask | ForEach-Object {
  $task = $_
  $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
  [PSCustomObject]@{
    TaskName = $task.TaskName
    TaskPath = $task.TaskPath
    LastRunTime = $info.LastRunTime
    LastTaskResult = $info.LastTaskResult
  }
} | Format-Table -AutoSize